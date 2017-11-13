# keylessProxy

最新中文文档：[go-keyless](https://www.sixianed.com/1507866347.html)

## 测试证书生成(基于OpenSSL自建CA颁发SSL证书)

1. 生成rsa私钥文件

		#openssl genrsa -out demo.key 2048
		Generating RSA private key, 2048 bit long modulus
		...............+++
		...............................+++
		e is 65537 (0x10001)

2. 生成证书签署请求

        # openssl req -new -key demo.key -out demo.csr
        You are about to be asked to enter information that will be incorporated
        into your certificate request.
        What you are about to enter is what is called a Distinguished Name or a DN.
        There are quite a few fields but you can leave some blank
        For some fields there will be a default value,
        If you enter '.', the field will be left blank.
        -----
        Country Name (2 letter code) [CN]:
        State or Province Name (full name) [GD]:
        Locality Name (eg, city) [Default City]:gz
        Organization Name (eg, company) [Default Company Ltd]:www.fastweb.com.cn
        Organizational Unit Name (eg, section) []:dev
        Common Name (eg, your name or your server's hostname) []:www.demo.cn
        Email Address []:liuheng@fastweb.com.cn
         
        Please enter the following 'extra' attributes
        to be sent with your certificate request
        A challenge password []:
        An optional company name []:
		
3. 用私有CA根据请求来签署证书

		# openssl x509 -req -in demo.csr -CA /etc/pki/CA/cacert.pem -CAkey /etc/pki/CA/private/cakey.pem -CAcreateserial -outform PEM -out demo.pem 
		Signature ok
		subject=/C=CN/ST=GD/L=gz/O=www.fastweb.com.cn/OU=dev/CN=demo/emailAddress=liuheng@fastweb.com.cn
		Getting CA Private Key
