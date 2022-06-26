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

The testing methodology will soon be updated with more edge-cases.

# Running a Benchmark
    ./benchmark.py
    options:
        --address ADDRESS, -a ADDRESS
                                Address of firegex backend
        --service_port SERVICE_PORT, -P SERVICE_PORT
                                Port of the Benchmark service
        --service_name SERVICE_NAME, -n SERVICE_NAME
                                Name of the Benchmark service
        --password PASSWORD, -p PASSWORD
                                Firegex password
        --num_of_regexes NUM_OF_REGEXES, -r NUM_OF_REGEXES
                                Number of regexes to benchmark with
        --duration DURATION, -d DURATION
                                Duration of the Benchmark in seconds
        --output_file OUTPUT_FILE, -o OUTPUT_FILE
                                Output results csv file
        --num_of_streams NUM_OF_STREAMS, -s NUM_OF_STREAMS
                                Output results csv file
        --new_istance, -i     Create a new service

Benchmarks let you evaluate the performance of the proxy. You can run one by typing in a shell  ```test.py -p FIREGEX_PASSWORD -r NUM_OF_REGEX -d BENCHMARK_DURATION -i```. 

It uses iperf3 to benchmark the throughput in MB/s of the server, both with proxy, without proxy, and for each new added regex. It will automatically add a new random regex untill it has reached NUM_OF_REGEX specified in the arguments. 

You will find a new benchmark.csv file containg the results.

# Firegex Performance Results

The test was performed on:
- AMD Ryzen 7 3700X (16 thread) @ 3.600GHz
- RAM Speed: 3200 MT/s (Dual Channel)
- Kernel: 5.18.5-arch1-1

Command: `python3 benchmark.py -r 100 -d 1 -s 50`

![Firegex Benchmark](/docs/FiregexBenchmark.png)
