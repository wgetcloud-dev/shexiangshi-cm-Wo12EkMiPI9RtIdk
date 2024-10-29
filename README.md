[合集 \- .NET云原生应用实践(4\)](https://github.com)[1\..NET云原生应用实践（二）：Sticker微服务RESTful API的实现10\-13](https://github.com/daxnet/p/18456878)[2\..NET云原生应用实践（一）：从搭建项目框架结构开始10\-09](https://github.com/daxnet/p/18172088)[3\..NET云原生应用实践（三）：连接到PostgreSQL数据库10\-22](https://github.com/daxnet/p/18470813)4\..NET云原生应用实践（四）：基于Keycloak的认证与授权10\-28收起
# 本章目标


1. 完成Keycloak的本地部署与配置
2. 在Stickers RESTful API层面完成与Keycloak的集成
3. 在Stickers RESTful API上实现认证与授权


# Keycloak的本地部署


Keycloak的本地部署最简单的方式就是使用Docker。可以根据官方文档构建Dockerfile，然后使用Docker Compose直接运行。由于Keycloak也是基础设施的一部分，所以可以直接加到我们在上一讲使用的docker\-compose.dev.yaml文件中。同样，在docker文件夹下新建一个keycloak的文件夹，然后新建一个Dockerfile，内容如下：



```


|  | FROM quay.io/keycloak/keycloak:26.0 AS builder |
| --- | --- |
|  |  |
|  | # Enable health and metrics support |
|  | ENV KC_HEALTH_ENABLED=true |
|  | ENV KC_METRICS_ENABLED=true |
|  |  |
|  | # Configure a database vendor |
|  | ENV KC_DB=postgres |
|  |  |
|  | WORKDIR /opt/keycloak |
|  | # for demonstration purposes only, please make sure to use proper certificates in production instead |
|  | RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore |
|  | RUN /opt/keycloak/bin/kc.sh build |
|  |  |
|  | FROM quay.io/keycloak/keycloak:26.0 |
|  | COPY --from=builder /opt/keycloak/ /opt/keycloak/ |
|  |  |
|  | ENTRYPOINT ["/opt/keycloak/bin/kc.sh"] |


```

然后修改docker\-compose.dev.yaml文件，加入一个名为stickers\-keycloak的新的service：



```


|  | stickers-keycloak: |
| --- | --- |
|  | image: daxnet/stickers-keycloak:dev |
|  | build: |
|  | context: ./keycloak |
|  | dockerfile: Dockerfile |
|  | environment: |
|  | - KC_DB=postgres |
|  | - KC_DB_USERNAME=postgres |
|  | - KC_DB_PASSWORD=postgres |
|  | - KC_DB_SCHEMA=public |
|  | - KC_DB_URL=jdbc:postgresql://stickers-pgsql:5432/stickers_keycloak?currentSchema=public |
|  | - KC_HOSTNAME=localhost |
|  | - KC_HOSTNAME_PORT=5600 |
|  | - KC_HTTP_ENABLED=true |
|  | - KC_HOSTNAME_STRICT=false |
|  | - KC_HOSTNAME_STRICT_HTTPS=false |
|  | - KC_PROXY=edge |
|  | - KC_BOOTSTRAP_ADMIN_USERNAME=admin |
|  | - KC_BOOTSTRAP_ADMIN_PASSWORD=admin |
|  | - QUARKUS_TRANSACTION_MANAGER_ENABLE_RECOVERY=true |
|  | command: [ |
|  | 'start', |
|  | '--optimized' |
|  | ] |
|  | depends_on: |
|  | - stickers-pgsql |
|  | ports: |
|  | - "5600:8080" |


```

在这些环境变量中，`KC_DB`指定了Keycloak所使用的数据库类型，我们打算复用上一讲中所使用的PostgreSQL数据库，所以这里填写`postgres`。`KC_DB_USERNAME`、`KC_DB_PASSWORD`、`KC_DB_SCHEMA`和`KC_DB_URL`指定了数据库的用户名、密码、schema名称以及数据库连接字符串。`KC_HOSTNAME`、`KC_HOSTNAME_PORT`指定了Keycloak运行的主机名和端口号，这个端口号需要跟`ports`里指定的对外端口号一致。`KC_BOOTSTRAP_ADMIN_USERNAME`和`KC_BOOTSTRAP_ADMIN_PASSWORD`指定了Keycloak默认的管理员名称和密码。


在启动Keycloak之前，还需要准备好PostgreSQL数据库，Keycloak启动后会自动连接数据库并创建数据库对象（表、字段、关系等等）。准备数据库也非常简单，继续沿用上一讲介绍的方法，在构建PostgreSQL数据库镜像的时候，将创建数据库的SQL文件复制到镜像中的`/docker-entrypoint-initdb.d`文件夹中即可。SQL文件包含以下内容：



```


|  | SET statement_timeout = 0; |
| --- | --- |
|  | SET lock_timeout = 0; |
|  | SET idle_in_transaction_session_timeout = 0; |
|  | SET client_encoding = 'UTF8'; |
|  | SET standard_conforming_strings = on; |
|  | SELECT pg_catalog.set_config('search_path', '', false); |
|  | SET check_function_bodies = false; |
|  | SET xmloption = content; |
|  | SET client_min_messages = warning; |
|  | SET row_security = off; |
|  |  |
|  | CREATE DATABASE stickers_keycloak WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'en_US.utf8'; |
|  | ALTER DATABASE stickers_keycloak OWNER TO postgres; |


```

然后重新构建并运行PostgreSQL和Keycloak容器：



```


|  | $ docker compose -f docker-compose.dev.yaml build |
| --- | --- |
|  | $ docker compose -f docker-compose.dev.yaml up |


```


> 强烈建议在重建和运行容器之前，清除本地的`stickers-pgsql:dev`镜像，并且删除`docker_stickers_postgres_data`卷，以确保旧数据不会影响新的部署。


在成功启动容器之后，打开浏览器访问http://localhost:5600，应该可以打开Keycloak的主页面并用admin/admin进行登录。


# 在Keycloak中配置Stickers Realm


限于篇幅，这里就不把配置Keycloak的整个过程一一展示出来了，请移步到我之前写的几篇文章查看详细步骤：


* 有关在Keycloak中实现多租户，并且对于单个租户下认证的配置，请参考《[在Keycloak中实现多租户并在ASP.NET Core下进行验证](https://github.com):[wgetCloud机场](https://tabijibiyori.org)》
* 有关在Keycloak的租户下启用授权机制，请参考《[Keycloak中授权的实现](https://github.com)》


请根据上面两篇文章的步骤，进行如下的配置：


1. 新建一个名为`stickers`的Realm
2. 切换到`stickers` Realm，新建一个名为`public`的Client
3. 在`public` Client下启用Direct access grants（暂时启用，用作测试）
4. 新建一个名为`usergroups`的Client Scope，在这个client scope中，添加一个类型为Group Membership的client scope。将其Token Claim Name设置为`groups`。然后将这个client scope添加到`public` Client下
5. 在`public` Client下新建两个角色：`administrator`和`regular_user`，然后新建三个用户：`daxnet`、`nobody`、`super`并设置密码，然后创建一个名为`public`的group（名称与Client的名称一致），在`public` group下，新建`users` group，再在`users` group下，新建`administrators` group。将`daxnet`添加到`users` group，将`super`添加到`administrators` group，并将`users` group赋予`regular_user`角色，将`administrators` group赋予`administrator`角色
6. 在`public` Client的Authorization配置中，创建四个Scope：`admin.manage_users`、`stickers.read`、`stickers.update`和`stickers.delete`；然后创建两个resource：`admin-api`，它具有a`dmin.manage_users` scope，以及`stickers-api`，它具有`stickers.read`、`stickers.update`和`stickers.delete`这三个scope
7. 在public Client下，创建两个基于角色的Policy：`require-admin-policy`，它分配了`administrator`角色，以及`require-registered-user-policy`，它分配了`regular_user`角色
8. 在Permissions下，创建四个Permission：
	1. admin\-manage\-users\-permission：基于`require-admin-policy`，作用在`admin.manage_users` Scope
	2. stickers\-view\-permission：基于`require-registered-user-policy`，作用在`stickers.read` Scope
	3. stickers\-update\-permission：基于`require-registered-user-policy`，作用在`stickers.update` Scope
	4. stickers\-delete\-permission：基于`require-registered-user-policy`，作用在`stickers.delete` Scope



> 你可以参考上面列出的两篇文章和这些步骤来配置Keycloak，也可以使用本章的代码直接编译Keycloak Docker镜像然后直接运行容器，Keycloak容器运行起来之后，所有的配置都会自动导入，此时就可以使用根据界面上的设置，比对上面的步骤进行学习了。


在完成Keycloak端的配置之后，就可以开始修改Stickers.WebApi项目，使我们的API支持认证与授权了。


# 在Stickers.WebApi中启用认证机制


关于什么是认证，什么是授权，这里就不多作讨论了，网上相关文章很多，也可以通过ChatGPT获得详细的解释和介绍。我们首先实现一个目标，就是只允许**注册用户**可以访问Stickers微服务，而不管这些用户是不是真的具有访问其中的某些API的**权限**。我这里用粗体字强调了“注册用户”和“权限”两个概念，也就可以区分出什么是认证，什么是授权了，通俗地说：认证就是该用户是否被允许使用网站的服务，授权就是在允许使用网站服务的前提下，该用户是否可以对其中的某些功能进行操作。


在ASP.NET Core中，集成认证与授权机制是非常容易的，首先，向Stickers.WebApi项目添加`Microsoft.AspNetCore.Authentication.JwtBearer` NuGet包，然后在Program.cs中，加入如下代码：



```


|  | builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme) |
| --- | --- |
|  | .AddJwtBearer(options => |
|  | { |
|  | options.Authority = "http://localhost:5600/realms/stickers"; |
|  | options.RequireHttpsMetadata = false; |
|  | options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters |
|  | { |
|  | NameClaimType = "preferred_username", |
|  | RoleClaimType = ClaimTypes.Role, |
|  | ValidateIssuer = true, |
|  | ValidateAudience = false |
|  | }; |
|  | }); |


```

上面的代码用来初始化ASP.NET Core的认证机制，我们使用Jwt Bearer Token的认证模块，在配置中，指定认证机构Authority为stickers Realm的Base URL，然后对token的认证进行参数配置。这里的`NameClaimType`指定了在解析access token的时候，应该将哪个Claim看成是用户名称，同理，`RoleClaimType`指定了应该将哪个Claim看成是用户角色。在启动了PostgreSQL和Keycloak容器之后，可以使用类似下面的cURL命令获得access token：



```


|  | $ curl --location 'http://localhost:5600/realms/stickers/protocol/openid-connect/token' \ |
| --- | --- |
|  | --header 'Content-Type: application/x-www-form-urlencoded' \ |
|  | --data-urlencode 'grant_type=password' \ |
|  | --data-urlencode 'client_id=public' \ |
|  | --data-urlencode 'client_secret=B2REunrXWN57KtQoJWoP2Dhr7gqKJrol' \ |
|  | --data-urlencode 'username=daxnet' \ |
|  | --data-urlencode 'password=daxnet' |


```

然后打开jwt.io，将这个access token复制到Debugger的Encoded部分，在Decoded部分可以看到，用户名是在preferred\_username字段指定的，这就是NameClaimType指定为`preferred_username`的原因：


![](https://img2024.cnblogs.com/blog/119825/202410/119825-20241026210008381-1316737186.png)


当然，还需要在Program.cs文件中加入Authentication和Authorization的Middleware：



```


|  | app.UseAuthentication(); |
| --- | --- |
|  | app.UseAuthorization(); |


```

并在StickersController上启用Authorize特性：



```


|  | [ApiController] |
| --- | --- |
|  | [Authorize] |
|  | [Route("[controller]")] |
|  | public class StickersController(ISimplifiedDataAccessor dac) : ControllerBase |
|  | { |
|  | // ... |
|  | } |


```

此时如果启动Stickers API，然后使用cURL获取所有的“贴纸”，则会返回401 Unauthorized：



```


|  | $ curl --location 'http://localhost:5141/stickers?asc=true&size=20&page=0' -v |
| --- | --- |
|  | * Host localhost:5141 was resolved. |
|  | * IPv6: ::1 |
|  | * IPv4: 127.0.0.1 |
|  | *   Trying [::1]:5141... |
|  | * Connected to localhost (::1) port 5141 |
|  | > GET /stickers?asc=true&size=20&page=0 HTTP/1.1 |
|  | > Host: localhost:5141 |
|  | > User-Agent: curl/8.5.0 |
|  | > Accept: */* |
|  | > |
|  | < HTTP/1.1 401 Unauthorized |
|  | < Content-Length: 0 |
|  | < Date: Sat, 26 Oct 2024 13:05:21 GMT |
|  | < Server: Kestrel |
|  | < WWW-Authenticate: Bearer |
|  | < |
|  | * Connection #0 to host localhost left intact |


```

但如果将刚刚获得的access token加到cURL命令中，就可以正常访问API了（access token太长，这里先把它截断了）：



```


|  | $ curl --location 'http://localhost:5141/stickers?asc=true&size=20&page=0' \ |
| --- | --- |
|  | --header 'Authorization: Bearer eyJh...' -v |
|  | * Host localhost:5141 was resolved. |
|  | * IPv6: ::1 |
|  | * IPv4: 127.0.0.1 |
|  | *   Trying [::1]:5141... |
|  | * Connected to localhost (::1) port 5141 |
|  | > GET /stickers?asc=true&size=20&page=0 HTTP/1.1 |
|  | > Host: localhost:5141 |
|  | > User-Agent: curl/8.5.0 |
|  | > Accept: */* |
|  | > Authorization: Bearer eyJh... |
|  | > |
|  | < HTTP/1.1 200 OK |
|  | < Content-Type: application/json; charset=utf-8 |
|  | < Date: Sat, 26 Oct 2024 13:08:06 GMT |
|  | < Server: Kestrel |
|  | < Transfer-Encoding: chunked |
|  | < |
|  | * Connection #0 to host localhost left intact |
|  | {"items":[],"pageIndex":0,"pageSize":20,"totalCount":0,"totalPages":0} |


```

# 在Stickers.WebApi中启用授权机制


在我之前写的《[ASP.NET Core Web API下基于Keycloak的多租户用户授权的实现](https://github.com)》一文中，已经详细介绍了如何基于Keycloak完成授权，在Stickers案例中，我会采用相同的实现方式，因此这里就不再赘述具体的实现过程了，仅介绍Stickers微服务所特有的部分。


上面我们已经在Keycloak中配置了授权，这里大致总结一下与授权相关的配置。首先，我们定义了四个scope，分别是：admin.manage\_users、stickers.read、stickers.update以及stickers.delete。所谓的scope，其实就是**对资源的操作类型**；然后，我们定义了两种**资源**：admin\-api和stickers\-api，分别表示两组不同的API：admin\-api表示与站点管理相关的API（虽然暂时我们还没有实现管理API），而stickers\-api则表示与“贴纸”相关的API（也就是StickersController所提供的API）；接下来，我们又定义了两个Policy：require\-admin\-policy和require\-registered\-user\-policy，分别表示“干某件事需要管理员角色”和“干某件事需要注册用户角色”。可以看到，其实基于角色的授权，在Keycloak的整个授权体系中，只是其中的一种特例，Keycloak所支持的Policy类型，并不仅只有基于角色这一种策略；最后，定义了四个Permission：admin\-manage\-users\-permission、stickers\-delete\-permission、stickers\-update\-permission和stickers\-view\-permission，这些permission都关联了对应的策略（这里都是基于角色的策略）和对资源的操作类型scope，而这些操作类型又进一步被资源所引用。所以，总的来说，Permission就定义了符合某种**策略**（Policy）的访问者对某种**资源**（Resource）具有完成何种**操作类型**（Scope）的权限。


仔细思考你会发现，我们其实根本不关心当前登录用户是什么角色，我们只关心该用户的**某些特质**是否达到**访问某种资源**并完成**相应操作**的需求，角色只不过是这些特质中的一种。所以，一方面在API上，我们定义该API是什么资源，它支持什么操作，而另一方面，当认证用户访问该API时，我们从用户的Claims中读取该用户在该资源上所能完成的操作名称，两者进行比对即可，而至于认证用户是否满足访问该资源并完成该操作的需求，在Keycloak的授权模块中就已经完成计算了，Keycloak只是在发送的token中带上计算结果就可以了。


下图展示了在Keycloak中，针对daxnet这个用户所进行的权限评估，从评估结果可以看到，该用户在stickers\-api资源上的stickers.read、stickers.update以及stickers.delete操作是具有权限的；而在admin\-api资源上的admin.manage\_users上是没有权限的。所以，我们只需要在Stickers.WebApi上实现这个判断就可以了。


![](https://img2024.cnblogs.com/blog/119825/202410/119825-20241028201214007-1170297541.png)


完成这个判断逻辑，大致会需要两个步骤：首先，使用access token，通过将`grant_type`设置成`urn:ietf:params:oauth:grant-type:uma-ticket`并再次调用`/realms/stickers/protocol/openid-connect/token`接口，以获得包含授权信息的user claims，然后，在API被访问时，根据该API所支持的操作列表，从带有授权信息的user claims中查找，看是否API所支持的操作在user claims中能被找到，如果能找到，就说明该用户可以访问API，否则就返回`403 Forbidden`。


完整代码这里就不详细介绍了，还是强烈建议移步阅读《[ASP.NET Core Web API下基于Keycloak的多租户用户授权的实现](https://github.com)》这篇博文，并配套本章节的源代码以了解细节。



> 这里还是涉及到user claims缓存的问题，因为在获取用户授权信息的时候，存在两次Keycloak的调用，这样做并特别高效，后续会考虑引入缓存机制来解决这个问题。


在完成代码的实现之后，就可以进行测试了，使用daxnet用户获取access token：



```


|  | $ curl --location 'http://localhost:5600/realms/stickers/protocol/openid-connect/token' \ |
| --- | --- |
|  | --header 'Content-Type: application/x-www-form-urlencoded' \ |
|  | --data-urlencode 'grant_type=password' \ |
|  | --data-urlencode 'client_id=public' \ |
|  | --data-urlencode 'client_secret=B2REunrXWN57KtQoJWoP2Dhr7gqKJrol' \ |
|  | --data-urlencode 'username=daxnet' \ |
|  | --data-urlencode 'password=daxnet' |


```

然后使用这个access token来访问`GET /stickers` API，可以看到，能够成功返回结果：



```


|  | $ curl --location 'http://localhost:5141/stickers' \ |
| --- | --- |
|  | --header 'Authorization: Bearer eyJhbGci......' \ |
|  | -v && echo |
|  | * Host localhost:5141 was resolved. |
|  | * IPv6: ::1 |
|  | * IPv4: 127.0.0.1 |
|  | *   Trying [::1]:5141... |
|  | * Connected to localhost (::1) port 5141 |
|  | > GET /stickers HTTP/1.1 |
|  | > Host: localhost:5141 |
|  | > User-Agent: curl/8.5.0 |
|  | > Accept: */* |
|  | > Authorization: Bearer eyJhbGci...... |
|  | > |
|  | < HTTP/1.1 200 OK |
|  | < Content-Type: application/json; charset=utf-8 |
|  | < Date: Mon, 28 Oct 2024 13:15:58 GMT |
|  | < Server: Kestrel |
|  | < Transfer-Encoding: chunked |
|  | < |
|  | * Connection #0 to host localhost left intact |
|  | {"items":[],"pageIndex":0,"pageSize":20,"totalCount":0,"totalPages":0} |


```

重新使用nobody用户获取access token：



```


|  | $ curl --location 'http://localhost:5600/realms/stickers/protocol/openid-connect/token' \ |
| --- | --- |
|  | --header 'Content-Type: application/x-www-form-urlencoded' \ |
|  | --data-urlencode 'grant_type=password' \ |
|  | --data-urlencode 'client_id=public' \ |
|  | --data-urlencode 'client_secret=B2REunrXWN57KtQoJWoP2Dhr7gqKJrol' \ |
|  | --data-urlencode 'username=nobody' \ |
|  | --data-urlencode 'password=nobody' |


```

然后使用这个access token来访问`GET /stickers` API，可以看到，API返回`403 Forbidden`：



```


|  | $ curl --location 'http://localhost:5141/stickers' \ |
| --- | --- |
|  | --header 'Authorization: Bearer eyJhbGci......' -v && echo |
|  | * Host localhost:5141 was resolved. |
|  | * IPv6: ::1 |
|  | * IPv4: 127.0.0.1 |
|  | *   Trying [::1]:5141... |
|  | * Connected to localhost (::1) port 5141 |
|  | > GET /stickers HTTP/1.1 |
|  | > Host: localhost:5141 |
|  | > User-Agent: curl/8.5.0 |
|  | > Accept: */* |
|  | > Authorization: Bearer eyJhbGci...... |
|  | > |
|  | < HTTP/1.1 403 Forbidden |
|  | < Content-Length: 0 |
|  | < Date: Mon, 28 Oct 2024 13:18:31 GMT |
|  | < Server: Kestrel |
|  | < |
|  | * Connection #0 to host localhost left intact |


```

# 总结


本文简单介绍了在Stickers.WebApi上基于Keycloak实现认证与授权的步骤，由于一些原理性的内容和具体实现细节在之前我的博文中都有详细介绍，所以这里也就不再重复了，建议可以结合这些文章来阅读本章代码，相信会有不少的收获。下一章会基于.NET Web Assembly实现前端，并在开发环境中调通整个前后端流程。


# 源代码


本章源代码在chapter\_4这个分支中：[https://gitee.com/daxnet/stickers/tree/chapter\_4/](https://github.com)


下载源代码前，请先删除已有的`stickers-pgsql:dev`和`stickers-keycloak:dev`两个容器镜像，并删除`docker_stickers_postgres_data`数据卷。


下载源代码后，进入docker目录，然后编译并启动容器：



```


|  | $ docker compose -f docker-compose.dev.yaml build |
| --- | --- |
|  | $ docker compose -f docker-compose.dev.yaml up |


```

现在就可以直接用Visual Studio 2022或者JetBrains Rider打开stickers.sln解决方案文件，并启动Stickers.WebApi进行调试运行了。


