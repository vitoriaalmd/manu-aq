<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">

    <style>
        body { 


            background-color: rgb(2,0,36);
background: linear-gradient(90deg, rgba(2,0,36,1) 0%, rgba(0,212,255,1) 81%);
;
            font: 14px sans-serif; 
        
            
    }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="justify-content-center align-items-center row">
            <div class="wrapper">
            <h2>Login</h2>
            <p>Please fill in your credentials to login.</p>


            <form action="" method="post">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" class="form-control">
                    <span class="invalid-feedback"></span>
                </div>    
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" class="form-control">
                    <span class="invalid-feedback"></span>
                </div>
                <div class="form-group">
                    <input type="submit" class="btn btn-primary" value="Login">
                </div>
                <p>Don't have an account? <a href="registro.php">Sign up now</a>.</p>
            </form>
            </div>
        </div>
    </div>
</body>
</html>