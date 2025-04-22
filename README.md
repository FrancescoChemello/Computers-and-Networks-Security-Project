# INTRUSION DETECTION SYSTEM - COMPUTERS AND NETWORKS SECURITY #
Computers and Networks Security - 2024/25

## Overview ##
This project implements a lightweight **Intrusion Detection System (IDS)** based on the **Aho-Corasick algorithm** for string matching. It is designed to detect malicious patterns in HTTP requests, such as *SQL injection* and *Shellshock attacks*.

The system includes:
* A custom implementation of the Aho-Corasick algorithm for *exact-matching* keyword detection.
* A basic HTTP server written in C to handle HTTP request.
* A real-time request analyzer that scans URLs, headers, and bodies.
* A modular structure to load and manage different attack patterns set from *'.txt'* files.

This project was developed as part of the [Computers and Networks Security](https://stem.elearning.unipd.it/course/view.php?id=10696) course.

*Computers and Networks Security* is a course of the [Master Degree in Computer Engineering](https://degrees.dei.unipd.it/master-degrees/computer-engineering/) of the  [Department of Information Engineering](https://www.dei.unipd.it/en/), [University of Padua](https://www.unipd.it/en/), Italy.

## Dependencies ##
Ensure that the following packages are installed before running the program:

* `gcc` (for compilation).
* `make` (for building the project).

### Installation on Debian-based systems:
```sh
sudo apt update && sudo apt install gcc make 
```

## Repository Structure ##
The repository is organised as follows:
* **src:** contains the main source code for the project.
    * **ahocorasick:** contains the script for the Aho-Corasick algorithm.
        * *ahocorasick.c*.
        * *ahocorasick.h*.
    * **http_parser:** contains the script for the HTTP parser.
        * *http_parser.c*.
        * *http_parser.h*.
    * **pattern:** contains the pattern in a *'.txt'* file.
        * *\*.txt*.
    * **server:** contains a simple implementation of an HTTP server.
        * *server.c*.
        * *server.h*.
    * *main.c*.
    * *main.h*.
    * **Makefile:** compilation instructions.
* README: project documentation. 

## How to run the program ##

### Compilation ###
To compile the program, run:

```sh
make main
```

### Execution ###
Run the program with the following syntax:

```sh
./main <file_list>
``` 
where:
   * file_list: a list of *.txt* files that contain malicious pattern to identify.

Example: 
```sh
./main command_injection.txt sql_injection.txt
```
This command launches the HTTP server and loads both *Shellshock* and *SQL injection* patterns for detection.

## How it works ##
The server listens on port ```8080``` and all incoming HTTP requests are parsed. Then, the *Aho-Corasick* engine checks:
* URL.
* Headers *(e.g. User-Agent)*.
* **POST** body.

If a pattern is matched, the server returns ```403 Forbidden - Forbidden: Malicious request detected!```, otherwise it returns ```200 OK - Hello user!```.

*Note: If the server accepts the request, it does not process it further. Regardless of the content, it always returns ```200 OK - Hello user!.```* 

## Testing ##

You can find automated test scripts in ```attack_test.sh```.

To run the test script first do:
```sh
chmod +x attack_test.sh 
```
to make it **executable**.

Then do:
```sh
./attack_test.sh
```
to **run** the script.

## How the Aho-Corasick Parser Works ##

This project implements a custom version of the **Aho-Corasick algorithm**. In this implementation, all *fail links* are set to the root node, and the parser logic follows a custom flow that minimizes false positives and maximizes detection accuracy.

### Core Logic ###

The parser reads the input **one character at a time** and performs a single traversal step in the trie. Based on the result of that step, it applies the following logic:

- **Did the traversal return to ROOT?**
  - **Yes: Am I currently reading a word?**
    - **Yes:** *Skip the entire word — it’s a bad match!*
    - **No:** *Was I already in ROOT before?*
      - **Yes:** *Continue to next character*.
      - **No:** *Is the previous character alphanumeric?*
        - **Yes:** *Continue to next character*.
        - **No:** *Restart from ROOT with this character*.
  - **No: Did I reach a terminal (leaf) node?**
    - **Yes: Is the next character NOT alphanumeric?**
      - **Yes:** *Match detected! - the match is printed to stdout for logging purposes*
      - **No:** *Skip the rest of the word — it may be a partial match! (e.g. SELECTED)*.
    - **No:** *Continue scanning*.

### Why This Approach Is Effective ###

- **Avoids false positives** by skipping partial or embedded keywords (e.g., ```SELECT``` in ```SELECTION```).
- **Prevents unnecessary rescanning** by skipping words early when mismatch is detected.
- **Improves match reliability** by reprocessing some characters if necessary (e.g., after early return to ROOT).

**Key insight:**  
Re-evaluating a character after falling into ROOT, rather than skipping it, helps catch valid patterns that might begin at that point. This small change significantly reduces missed matches and improves parsing accuracy.

### License ###

All the contents of this repository are shared using the [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/).

![CC logo](https://i.creativecommons.org/l/by-sa/4.0/88x31.png)