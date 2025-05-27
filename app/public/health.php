<?php

http_response_code(200);
echo "OK";
// This file is used to check the health of the application.
// It returns a 200 OK response if the application is running correctly.
// This is useful for load balancers and monitoring systems to ensure the app is up.
// You can customize the response message if needed, but a simple "OK" is often sufficient.
