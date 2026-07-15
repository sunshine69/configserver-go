# configserver-go
Simple configserver in go

Support backend filesystem and postgres. I am not going to implement git backend as I never think git is suitable place for config.

This server now allow upload to deploy config files using its own API.

Look at the test script and readme-specs.md for what it offers you. And then the sample config.yaml.

# Quick start 

Read docker-compose - run 

```
docker compose up -d --build 
```

Now you can access the server via http://localhost:7777

Try to run ./test_all.sh.

Or play around with curl.
