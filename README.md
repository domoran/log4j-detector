# log4j-detector rewrite

Based on this repository: https://github.com/mergebase/log4j-detector

Rewritten Version for more speed: Log4JScan

# log4j-detector

Detects log4j versions on your file-system, including deeply recursively nested copies (jars inside jars inside jars).
Works on Linux, Windows, and Mac, and everywhere else Java runs, too!

Currently detects log4j-core versions 2.12.2, 2.15.0 and 2.16.0 as SAFE.  All other versions as VULNERABLE (although it does report pre-2.0-beta9 as "POTENTIALLY_SAFE").

Can correctly detect log4j inside executable spring-boot jars/wars, as well as dependencies blended into [uber jars](https://mergebase.com/blog/software-composition-analysis-sca-vs-java-uber-jars/) and shaded jars.

# Example Usage:
java -jar log4j-detector-2021.12.14.jar [path-to-scan] > hits.txt

![Terminal output from running java -jar log4j-detector.jar in a terminal](./log4j-detector.png)

# More Example Usage:

```
<<<<<<< HEAD
java -jar log4j-detector-2021.12.15.jar /var/tmp/l 
=======
java -jar log4j-detector-2021.12.14.jar /var/tmp/l 
>>>>>>> Initial Version

/var/tmp/l/log4j-core-2.10.0.jar contains Log4J-2.x   >= 2.10.0 _VULNERABLE_ :-(
/var/tmp/l/log4j-core-2.12.2.jar contains Log4J-2.x   >= 2.12.2 _SAFE_ :-)
/var/tmp/l/log4j-core-2.14.1.jar contains Log4J-2.x   >= 2.10.0 _VULNERABLE_ :-(
<<<<<<< HEAD
/var/tmp/l/log4j-core-2.15.0.jar contains Log4J-2.x   >= 2.15.0 _OKAY_ :-|
/var/tmp/l/log4j-core-2.16.0.jar contains Log4J-2.x   >= 2.16.0 _SAFE_ :-)
```

# Why Report About 2.10.0, 2.15.0, and 2.16.0 ?

We consider version 2.10.0 important because that's the first version where message lookups can be disabled via config.

We consider version 2.15.0 important because that's the first version where default config is not vulnerable to CVE-2021-44228.

And version 2.16.0 is important because it's not vulnerable to CVE-2021-45046. Despite CVE-2021-45046 being much less serious,
we anticipate everyone will want to patch to 2.16.0.

# What are those "file1.war!/path/to/file2.zip!/path/to/file3.jar!/path/to/log4j.jar" results about?

The "!" means the log4j-detector entered a zip archive (e.g., *.zip, *.ear, *.war, *.aar, *.jar). Since zip files can
contain zip files, a single result might contain more than one "!" indicator in its result.

Note:  the log4j-detector only recursively enters zip archives. It does not enter tar or gz or bz2, etc. The main reason
being that Java systems are often configured to execute jars inside jars, but they are never configured to execute other
file formats (that I know of!). And so a log4j copy inside a *.tar.gz is probably not reachable for a running Java
system, and hence, not a vulnerability worth reporting.

2nd note:  for zips-inside-zips our scanner does load the inner-zip completely into memory (using ByteArrayInputStream)
before attempting to scan it. You might need to give Java some extra memory if you have extremely large inner-zips on
your system (e.g., 1 GB or larger).

# Usage

```
java -jar log4j-detector-2021.12.15.jar 

Usage: java -jar log4j-detector-2021.12.15.jar [--verbose] [paths to scan...]
=======
/var/tmp/l/log4j-core-2.15.0.jar contains Log4J-2.x   >= 2.15.0 _SAFE_ :-)
/var/tmp/l/log4j-core-2.16.0.jar contains Log4J-2.x   >= 2.15.0 _SAFE_ :-)
```

# Caveats

- It currently skips directories / files that current user does not have permission to read.  It does not say anything about this.
- It ignores symlinks (and similarly says nothing about this).

We plan to fix both of these issues by December 15th, 2021.

# What are those "file1.war!/path/to/file2.zip!/path/to/file3.jar!/path/to/log4j.jar" results about?
The "!" means the log4j-detector entered a zip archive (e.g., *.zip, *.ear, *.war, *.aar, *.jar).  Since zip files can contain zip files, a single result might contain more than one "!" indicator in its result.

Note:  the log4j-detector only recursively enters zip archives.  It does not enter tar or gz or bz2, etc. The main reason being that Java systems are often configured to execute jars inside jars, but they are never configured to execute other file formats (that I know of!).  And so a log4j copy inside a *.tar.gz is probably not reachable for a running Java system, and hence, not a vulnerability worth reporting.

2nd note:  for zips-inside-zips our scanner does load the inner-zip completely into memory (using ByteArrayInputStream) before attempting to scan it.  You might need to give Java some extra memory if you have extremely large inner-zips on your system (e.g., 1 GB or larger).

# Usage
```
java -jar log4j-detector-2021.12.14.jar 

Usage: java -jar log4j-detector-2021.12.14.jar [--verbose] [paths to scan...]
>>>>>>> Initial Version

Exit codes:  0 = No vulnerable Log4J versions found.
             2 = At least one vulnerable Log4J version found.

<<<<<<< HEAD
About - MergeBase log4j detector (version 2021.12.15)
=======
About - MergeBase log4j detector (version 2021.12.14)
>>>>>>> Initial Version
Docs  - https://github.com/mergebase/log4j-detector 
(C) Copyright 2021 Mergebase Software Inc. Licensed to you via GPLv3.
```

# Build From Source:
<<<<<<< HEAD

=======
>>>>>>> Initial Version
```
git clone https://github.com/mergebase/log4j-detector.git
cd log4j-detector/
mvn install
<<<<<<< HEAD
java -jar target/log4j-detector-2021.12.15.jar
```

# License

GPL version 3.0

# How Does It Work?

The Java compiler stores String literals directly in the compiled *.class files. If log4j-detector detects a file
named "JndiManager.class"
on your file-system, it then examines that file for this String: "Invalid JNDI URI - {}". Turns out that specific String
literal is only present in the patched version of Log4J (version 2.15.0). Any versions of Log4J without that String are
vulnerable.

# What About Log4J 1.2.x ?

Only versions of Log4J 2.x (from 2.0-beta9 to 2.14.1) are vulnerable to CVE-2021-44228.

# How Can I Be Sure This Isn't A Trojan Pretending To Be A Log4J Detector?

Great question! Since we include the complete source code here in Github (all 750 lines of Java), as well as the steps
to build it, and since this tool has zero dependencies, it shouldn't take too long to carefully study the code to your
satisfaction. If you don't trust Maven you can go directly into the "src/main/java/com/mergebase/log4j" directory and
type "javac \*.java". That works, too!

# What Is MergeBase All About?

[MergeBase](https://mergebase.com/) is an SCA company (Software Composition Analysis) based in Vancouver, Canada. We're
similar to companies like Snyk, Sonatype, Blackduck, etc., in that we help companies detect and manage vulnerable
open-source libraries in their software. Check us out! We have great accuracy, great language support, and we're not too
expensive, either: [mergebase.com/pricing](https://mergebase.com/pricing/).

We offer 2-week free trials of our SCA product [https://mergebase.com/try/](https://mergebase.com/try/). But if you email our CEO (oscar@mergebase.com) with the subject "log4j-detector" we will extend your free trial to 4-weeks.
=======
java -jar target/log4j-detector-2021.12.14.jar
```

# License
GPL version 3.0

# How Does It Work?
The Java compiler stores String literals directly in the compiled *.class files.  If log4j-detector detects a file named "JndiManager.class"
on your file-system, it then examines that file for this String: "Invalid JNDI URI - {}".  Turns out that specific String literal
is only present in the patched version of Log4J (version 2.15.0).  Any versions of Log4J without that String are vulnerable.

# What About Log4J 1.2.x ?
Only versions of Log4J 2.x (from 2.0-beta9 to 2.14.1) are vulnerable to CVE-2021-44228.

# How Can I Be Sure This Isn't A Trojan Pretending To Be A Log4J Detector?
Great question! Since we include the complete source code here in Github (all 600 lines of Java), as well as the steps to build it, and since this tool has zero dependencies, it shouldn't take too long to carefully study the code to your satisfaction. If you don't trust Maven you can go directly into the "src/main/java/com/mergebase/log4j" directory and type "javac \*.java".  That works, too!

# What Is MergeBase All About?
[MergeBase](https://mergebase.com/) is an SCA company (Software Composition Analysis) based in Vancouver, Canada. We're similar to companies like Snyk, Sonatype, Blackduck, etc., in that we help companies detect and manage vulnerable open-source libraries in their software. Check us out! We have great accuracy, great language support, and we're not too expensive, either: [mergebase.com/pricing](https://mergebase.com/pricing/)
>>>>>>> Initial Version


