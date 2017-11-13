---
nav-sort: 110
nav-level: 1
---
# Command Line Binary Release
The command line binary release is a pure Java, platform neutral, command line UI. It requires a Java 8 Runtime to be installed.

## Download
All Symohony REST Tools releases are available from the releases page at https://github.com/symphonyoss/symphony-rest-tools/releases.

The command line UI is called **symphony-rest-tools-cmdline-X.Y.Z-bin.tar.gz**

This is the pure Java, platform neutral, command line implementation. Note that the command line scripts are also included in each of the UI distributions as well, so you may prefer to install one of them instead.

## Install
There is no installation process as such, simply extract the tarball in a convenient location. Once you do that you should see a file structure similar to this

```
$ tree
.
├── bash
│   ├── checkCerts
│   ├── checkPod
│   ├── environment.sh
│   ├── jcurl
│   └── probePod
├── bat
│   ├── checkCerts.bat
│   ├── checkPod.bat
│   ├── environment.bat
│   ├── jcurl.bat
│   └── probePod.bat
├── certs
│   └── test
│       ├── 127.0.0.1.p12
│       ├── bot.user1-no-root.p12
│       ├── bot.user1.p12
│       ├── bot.user10.p12
```
many similar lines not shown
```
│       ├── server.keystore
│       ├── server.truststore
│       ├── server.truststore.2
│       ├── server.truststore.3
│       ├── wildcard.keystore
│       └── wildcard.symphony.com.p12
└── lib
    ├── bcpkix-jdk15on-1.51.jar
    ├── bcprov-jdk15on-1.51.jar
    ├── jackson-annotations-2.8.7.jar
    ├── jackson-core-2.8.7.jar
    ├── jackson-databind-2.8.7.jar
    ├── jcurl-0.9.7.jar
    ├── jsr305-3.0.2.jar
    └── org.symphonyoss.symphony.tools.rest-0.1.6.jar

5 directories, 85 files
```

The **bash** directory contains shell scripts for Unix based systems, the **bat** directory contains Windows batch file scripts which do the same thing for that platform.

The **certs** directory contains a set of test certificates which can be used as examples _**for non-production purposes only**_.

## Run
The launch scripts pass through command line parameters so you can simply type the name of the script followed by additional parameters to run the various commands.

### Switches
Switches are single letter parameters introduced by a single hyphen. Switches can be concatenated in a single command line argument and some of them can be specified multiple times so the following would all be valid:

```
$ someCommand -i -v
$ someCommand -iv
$ someCommand -iivvv
```

Note that most of the launch scripts add **-ii** (which causes all required and optional flags to be prompted for) so adding -i to the launch scripts will result in the following error:

```
$ bash/probePod -v -i
Exception in thread "main" org.symphonyoss.symphony.tools.rest.util.command.CommandLineParserFault: 
  Switch "i" may be set at most 2 times
```
There are some [Common Switches](../CommonSwitches.md) which can be applied to most commands.

### Flags
A Flag is a named parameter. From the command line flags are entered as a parameter with double hyphen or a Unicode em-dash as an introducer and a variable length name, followed by a separate parameter containing the flag value. So a command which has a flag called storetype which also takes the switches above, could be entered as:

_example -qa --storetype pkcs12_

There are some [Common Flags](../CommonFlags.md) which can be applied to several commands.

## Probe Pod
To make a start, try running the [Probe Pod](../Commands/ProbePod.md) command. This tries to identify the configuration for a pod given nothing more than a host name.

The Probe Pod command requires a host name, and also accepts parameters to specify key and trust stores. The launch scripts include the flag **-ii** which cause all required and optional parameters to be prompted for when a command is run.

The values of all parameters are saved and are offered as the default value when the next command is run.

If you are running on OSX or Linux type the command

```
$ bash/probePod
```

If you are running on Windows then type the command

```
$ bat\probePod.bat
```

Assuming you have not previously used Symphony REST Tools, a configuration directory will be automatically created in the default place, which is **.srt** in your home directory:

```
$ bash/probePod 
Default home area "/Users/yourname/.srt" created.
SRT_HOME set by Default
Press RETURN to accept default values
Enter a space to clear the default value
Leading and trailing whitespace are deleted
```
You will then be prompted for the parameters of the Probe Pod command. As the prompt says, you can simply press _RETURN_ to accept the default value shown in square brackets, and leading and trailing whitespace are removed from responses, so if you enter a single space that will clear the default and enter an empty value, should you wish to do so.

When prompted for a host name enter the name of your pod (you can omit the .symphony.com) or try **foundation-dev**.

If you provide a keystore and truststore then the command will try to authenticate to the pod, which gives a more accurate and reliable result, but in most cases a good result is obtained without these, so you can accept the empty default values for now:
```
Location of SRT home[]: 
Host Name[]: foundation-dev
Keystore File Name[]: 
Keystore Type[pkcs12]: 
Keystore Password[changeit]: 
Truststore File Name[]: 
Truststore Type[jks]: 
Truststore Type[changeit]: 
name=foundation-dev
domain=.symphony.com


Probing foundation-dev.symphony.com for a Pod
=============================================
Probing for Pod
===============
```
For more specific details about what this command is doing, see the [Probe Pod](../Commands/ProbePod.md) command page.
