# Firegex tests

## [GO BACK](../README.md)

Tests are a quick and dirty way to check if your modification to the backend code dind't break anything.

# Running a Test
    $ ./test.py 
    usage: test.py [-h] [--address ADDRESS] [--service_port SERVICE_PORT] [--service_name SERVICE_NAME] --password PASSWORD

If you are running firegex locally, just run ```test.py -p FIREGEX_PASSWORD```. Otherwise, select a remote address with  ```-a http://ADDRESS:PORT/``` .

Output of the tests:

    Testing will start on http://127.0.0.1:5000/
    Sucessfully logged in ✔
    Sucessfully created service Test Service with public port 1337 ✔
    Sucessfully received the internal port 38222 ✔
    Sucessfully started service with id test-service ✔
    Successfully tested first proxy with no regex ✔
    Sucessfully added regex to service with id test-service ✔
    The malicious request was successfully blocked ✔
    Sucessfully stopped service with id test-service ✔
    The request wasn't blocked ✔
    Sucessfully delete service with id test-service ✔

The testing methodology will soon be updated with more edge-cases and a benchmarking tool to evauate the speed and effecitveness of our proxy.