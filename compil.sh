
rm -f audisp-simplify-c.o
rm -f audisp-simplify-c-thread.o
rm -f audisp-simplify-c-str-function.o
rm -f audisp-simplify-c-filter.o
rm -f audisp-simplify-c
rm -f /bin/audisp-simplify-c

gcc -c audisp-simplify-c-filter.cpp
gcc -c audisp-simplify-c-str-function.cpp
gcc -c audisp-simplify-c-thread.cpp
gcc -c audisp-simplify-c-d.cpp
gcc -o audisp-simplify-c audisp-simplify-c.o audisp-simplify-c-thread.o audisp-simplify-c-str-function.o audisp-simplify-c-filter.o -lstdc++ -lm -lpthread -lz

chmod 755 audisp-simplify-c
cp -pv audisp-simplify-c /bin/
systemctl restart auditd
