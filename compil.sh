rm -f /bin/audisp-simplify-c
if [ `uname -p` == 'x86_64' ]
then
    echo '64bit'
    gcc audisp-simplify-c.cpp -o audisp-simplify-c -lstdc++ -lm
else
    gcc audisp-simplify-c.cpp -o audisp-simplify-c -lstdc++ -lm
fi

chmod 755 audisp-simplify-c
cp -pv audisp-simplify-c /bin/
