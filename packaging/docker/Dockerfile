FROM alfresco/alfresco-base-tomcat:8.5.34-java-11-openjdk-centos-7

RUN mkdir -p /usr/local/tomcat/shared/classes/alfresco/web-extension
RUN mkdir -p /usr/local/tomcat/amps_share

COPY target/war /usr/local/tomcat/webapps
COPY target/alfresco-mmt/* /usr/local/tomcat/alfresco-mmt/
COPY target/amps_share /usr/local/tomcat/amps_share

COPY target/classes/web-extension-samples/share-config-custom.xml /usr/local/tomcat/shared/classes/alfresco/web-extension
COPY target/classes/web-extension-samples/custom-slingshot-application-context.xml.sample /usr/local/tomcat/shared/classes/alfresco/web-extension
COPY target/classes/web-extension-samples/smartfolders-amp-actions-config.xml /usr/local/tomcat/shared/classes/alfresco/web-extension

# not sure if this is needed for share:
RUN sed -i "s/shared.loader=/shared.loader=\${catalina.base}\/shared\/classes/" /usr/local/tomcat/conf/catalina.properties

COPY substituter.sh /usr/local/tomcat/shared/classes/alfresco
RUN chmod +x /usr/local/tomcat/shared/classes/alfresco/substituter.sh

RUN mkdir /usr/local/tomcat/keystore
COPY target/tls/* /usr/local/tomcat/keystore/

RUN sed -i "s/\    <\/Engine>/\n\    <\/Engine>\n\    <Connector\ port=\"8443\"\ URIEncoding=\"UTF-8\"\ protocol=\"org.apache.coyote.http11.Http11Protocol\"\ SSLEnabled=\"true\"\n\               maxThreads=\"150\"\ scheme=\"https\"\ keystoreFile=\"\/usr\/local\/tomcat\/keystore\/ssl.keystore\"\ keystorePass=\"kT9X6oe68t\"\ keystoreType=\"JCEKS\"\n\ secure=\"true\"\ connectionTimeout=\"240000\"\ truststoreFile=\"\/usr\/local\/tomcat\/keystore\/ssl.truststore\"\ truststorePass=\"kT9X6oe68t\"\ truststoreType=\"JCEKS\"\n\               clientAuth=\"want\"\ sslProtocol=\"TLS\"\ allowUnsafeLegacyRenegotiation=\"true\"\ maxHttpHeaderSize=\"32768\"\ maxSavePostSize=\"-1\" \/>/g" /usr/local/tomcat/conf/server.xml

# apply amps
RUN java -jar /usr/local/tomcat/alfresco-mmt/alfresco-mmt*.jar install \
              /usr/local/tomcat/amps_share /usr/local/tomcat/webapps/share -directory -nobackup -force

EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/tomcat/shared/classes/alfresco/substituter.sh", "catalina.sh run"]