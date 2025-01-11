
rm -f audisp-simplify-c.o
rm -f audisp-simplify-c-thread.o
rm -f audisp-simplify-c-str-function.o
rm -f audisp-simplify-c-filter.o
rm -f audisp-simplify-c
rm -f /bin/audisp-simplify-c
if [ `uname -p` == 'x86_64' ]
then
    echo '64bit'
    gcc -c audisp-simplify-c-filter.cpp
    gcc -c audisp-simplify-c-str-function.cpp
    gcc -c audisp-simplify-c-thread.cpp
    gcc -c audisp-simplify-c.cpp
    gcc -o audisp-simplify-c audisp-simplify-c.o audisp-simplify-c-thread.o audisp-simplify-c-str-function.o audisp-simplify-c-filter.o -lstdc++ -lm -lpthread

    #gcc audisp-simplify-c.cpp -o audisp-simplify-c -lstdc++ -lm -lpthread
else
    gcc -c audisp-simplify-c-filter.cpp
    gcc -c audisp-simplify-c-str-function.cpp
    gcc -c audisp-simplify-c-thread.cpp
    gcc -c audisp-simplify-c.cpp
    gcc -o audisp-simplify-c audisp-simplify-c.o audisp-simplify-c-thread.o audisp-simplify-c-str-function.o audisp-simplify-c-filter.o -lstdc++ -lm -lpthread
fi

chmod 755 audisp-simplify-c
cp -pv audisp-simplify-c /bin/
systemctl restart auditd
