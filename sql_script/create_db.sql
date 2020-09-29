-- create the user on the master database
USE [master]
GO
CREATE LOGIN [test_user] WITH PASSWORD=N'P@ssW0rd1234!', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
CREATE USER [test_user] FOR LOGIN [test_user]
GO

-- create database
CREATE DATABASE my_test_db
GO

-- create the user on the target database for the login
USE [my_test_db]
GO
CREATE USER [test_user] FOR LOGIN [test_user]
-- add the user to the desired role
ALTER ROLE [db_owner] ADD MEMBER [test_user]
-- need sysadmin role to be able to see sql agent
ALTER SERVER ROLE [sysadmin] ADD MEMBER [test_user]
GO
