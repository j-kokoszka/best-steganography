rm -f test_*.pcap
for i in {1..7}; do
    sudo tcpdump -eni lo -w test_$i.pcap &
    > received_data.txt
    python3 sender_xor.py http://127.0.0.1:5000 Sofokles-Antygona.txt
    diff -q Sofokles-Antygona.txt received_data.txt > /dev/null
    [ "$?" == 0 ] && echo "[$i] ok" || echo "[$i] notok"
    > decrypted_data.txt
    python3 checker_app.py test_$i.pcap
    diff -q Sofokles-Antygona.txt decrypted_data.txt > /dev/null
    [ "$?" == 0 ] && echo "[$i] checker ok" || echo "[$i] checker notok"
    kill $(jobs -p)
done