# mycd00r Directory

## encrypt/
This was an attempt to encrypt the executable based on a profile of the target machine that we want to execute on. It is not finished and has been moved to the sideline for now.

## include/
This directory holds the include files for the implant. 

### attacks.h
Holds function declarations of the attacks that can be used. Currently there is only bind_shell() and rev_shell().

### backdoor_utils.h
Holds function declarations and macros regarding the activation methods of the backdoor. Currently the two activation methods are port knock and magic bytes. The acitvation method is defined at compile time. Additionally, the cdr_open_door function will execute when the activation method is met, what it executes is determined at compile time.

One way to test the rev_shell() function is to set up a listener on a separate device. When compiling using the compiler.py in src/buildScripts/ add the -atkR flag to specify a reverse shell. Additionally add the -revip and -revport flags to specify the IP address and port number that the reverse shell tries to connect to.

On the other device generate a certificate and key with this command:

```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Then set up a socat listener with this command:

```
socat OPENSSL-LISTEN:<port>,reuseaddr,cipher=DEFAULT,cert=cert.pem,key=key.pem,verify=0 -
```

This will set up a socat listener using TLS/SSL, and the reverse shell will connect to it.

### utils.h
Holds function declarations and macros that are useful across files.

### validators.h
Holds function declarations and macros that are used to validate that the machine the implant is running on is valid.

## lib/
Holds the definitions of the functions from the include/ directory.

## scripts/
Just holds scripts that might be useful.

## stub/
The file in the stub/ directory is an attempt to implement the environmental keying along with the encrypt/ directory. It is not finished and has been moved to the sideline for now.