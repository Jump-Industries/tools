import sys
import os

def main():

    rule_file =open("generated.rules","w")
    x = 0
    sid = 1

    with rule_file as f:
        header_rules_count = int(sys.argv[1])

        for l in range(255):
            l += 1
            if x == header_rules_count:
                break

            for k in range(255):
                k += 1
                if x == header_rules_count:
                    break

                for j in range(255):
                    j += 1
                    if x == header_rules_count:
                        break

                    for i in range(255):
                        i += 1
                        f.write("alert ip " + str(l) + "." + str(k) + "." + str(j) + "." + str(i) +
                                " any -> any any (msg:\"dummy header rule " + str(x) + "\"; sid:" + str(sid) + ";)")
                        x += 1
                        sid += 1
                        f.write("\n")
                        if x == header_rules_count:
                            break

        x=0
        payload_rules_count = int(sys.argv[2])
        for l in range(payload_rules_count):
            f.write("alert ip any any -> any any (msg:\"dummy content rule " + str(x) + "\"; " +
                    "content:\"ABCDEFG" + str(x) + "\"; sid: " + str(sid) + ";)")
            x += 1
            sid += 1
            f.write("\n")
            if x == payload_rules_count:
                break








        f.close()
if __name__ == '__main__':
    main()
