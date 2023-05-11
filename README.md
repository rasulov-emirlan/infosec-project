# usage

Make sure to be at the root of our project. And please install docker if you do not have it.

```
docker build -t infosec-project ./
```

```
docker run infosec-project pcap/null_scan.pcap
```

Now you should see something like this
![example image](https://github.com/rasulov-emimrlan/infosec-project/blob/master/images/example.png?raw=true)

# keep in mind

We place pcap files inside of the pcap directory and only there. If you add new files or delete existing ones, make sure to rebuild the image.
