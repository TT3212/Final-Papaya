#!/bin/sh

docker build --tag apache .
docker run --name apache2 -itd -p 7777:7777 apache

