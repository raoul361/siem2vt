# siem2vt
Script to send hashes from SIEM to VirusTotal; then to syslog for automated action.

The intention here is to check hashes from specific events (such as an administrator override/UAC allow, etc.) that are picked up by SIEM. If the file in question is malicious, you can then take an action, to be triggered by the resultant syslog message.


```
      _                ____        _   
  ___(_) ___ _ __ ___ |___ \__   _| |_ 
 / __| |/ _ \ '_ ` _ \  __) \ \ / / __|
 \__ \ |  __/ | | | | |/ __/ \ V /| |_ 
 |___/_|\___|_| |_| |_|_____| \_/  \__|       
```

Check hashes (md5, sha) against VirusTotal for matches. If there is a match, returns the virus signature for a given AV engine and the number of positive hits.

## Arguments

**hash** - the md5/sha hash to check
**engine** - the AV engine to use (e.g. McAfee, Kaspersky)
**message** - the prefix for the syslog message; this makes later parsing easier (e.g. regex based on this text within your automation tool)

## Dependencies

```
pip install virustotal
```

## API Key

Requires a [virustotal.com] (https://www.virustotal.com/en/documentation/virustotal-community/) (free) API key.
