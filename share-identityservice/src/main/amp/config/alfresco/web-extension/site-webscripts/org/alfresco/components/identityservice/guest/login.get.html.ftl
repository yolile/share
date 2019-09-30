<@markup id="identityservice-loginredirect-html" target="form" action="after" scope="global" group="login">
    <@uniqueIdDiv>

        ${message}

        <form id="${args.htmlid?html}-form-identityservice"
              method="post" action=""
              value="${args.htmlid?html}-form-identityservice"
              name="${args.htmlid?html}-form-identityservice">

            <p style="text-align:left; padding-bottom:20px;">
                <#--${msg("identityservice.share.login.idp.info", "<a href=\"" + "\">Identity Service</a>")}-->
            </p>
        </form>
    </@>
</@>
