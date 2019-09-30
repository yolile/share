function main()
{
/*    model.loginUrl = "http://localhost:8082/auth/" +
        "realms/alfresco/protocol/openid-connect/auth?" +
        "response_type=code&" +
        "client_id=alfresco&" +
        "login=true&" +
        "scope=openid&" +
        "redirect_uri=" + encodeURI("https://localhost:9443/share/page/identity-service/login");*/

    var result = remote.connect("alfresco-noauth").get("/internal/identity-service/loginurl");
    if (result.status == 200)
    {
        model.message = "merge";
    }
    else
    {
        model.message = "NU merge";
    }
}

main();