<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>

<h1>Authenticated User: <span style="color:green;"><shiro:principal/></span></h1>
<br />

<shiro:hasRole name="shiro-app:admin">
    <b>
        User has role: <span style="color:green;">shiro-app:admin</span>
    </b><br />
</shiro:hasRole>

<shiro:hasPermission name="payroll:run">
    <b>
        User has permission: <span style="color:green;">payroll:run</span>
    </b><br />
</shiro:hasPermission>


