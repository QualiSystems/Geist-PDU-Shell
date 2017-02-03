IFS='.' read -a vers < package/version.txt

oldvers="${vers[0]}.${vers[1]}.${vers[2]}"
newvers="${vers[0]}.${vers[1]}.$(expr ${vers[2]} + 1)"

sed -i -e "s/$oldvers/$newvers/" package/version.txt geist_pdu/version.txt geist_pdu/shell.yml geist_pdu/src/requirements.txt

cd package
python setup.py sdist --format zip
mv -v dist/*.zip /c/Quali/python-offline-repo3
cd ..

cd geist_pdu
shellfoundry install
cd ..
