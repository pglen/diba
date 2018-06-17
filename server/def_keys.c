
/* =====[ def_keys.c ]=========================================================

   Description:     Just a pair of keys to use.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jun.16.2018     Peter Glen      Initial version.

   ======================================================================= */

// A basic pair of public and private key.
// Used in development, can be used as testing and fallback.
// Pass for the key is '1111' (no quotes)

char mykey[] = "\
-----BEGIN DIGIBANK RSA PUBLIC KEY-----\n\
KDEzOmRpYmFjcnlwdC1rZXkoMTc6S2V5IENyZWF0aW9uIERhdGUxOToyMDE3LzEy\n\
LzIxIDAxOjA5OjI2KSgxMTpLZXkgVmVyc2lvbjU6MC4wLjQpKDg6S2V5IE5hbWUx\n\
MTp1bm5hbWVkIGtleSkoODpLZXkgVHlwZTM6UlNBKSgxNTpLZXkgRGVzY3JpcHRp\n\
b24xNDpubyBkZXNjcmlwdGlvbikoNjpLZXkgSUQzMjpONEV5M1R2bldxbE1JcTlG\n\
eUlrSkovZ2k1clpQbWl6TCkoMTE6S2V5IENyZWF0b3I5OnBldGVyZ2xlbikoMTI6\n\
S2V5IEhvc3RuYW1lMzpIUDIpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgx\n\
MTpQdWJsaWMgSGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lL\n\
bDdEWFVSa3RPYlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlBy\n\
aXZhdGUgSGFzaDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxa\n\
dGxZUlpVR1U9KSkoMTA6cHVibGljLWtleSgzOnJzYSgxOm4yNTc6AMgFTcDA/WGw\n\
TVdBuSHOyTIva2gOJcbWXuU/siYOHu594eIgn+O4fyhkp2VQM1rT5LSFjWLb4KTT\n\
A5apU5ibXF0BOzEYgN2swOfTJ2Iw3iu/aftEfKEhLaUIi8gOgZJHJNuXxUOg0+I2\n\
2f69s0DnTXXcbeuZXPZxI0wirrP5CafuSjPSH+fmrmJM08biJQ0TRmFiOOc7f95H\n\
jcnh9kPkJy7ucS4Nl7FsXqFJ+ZZn74FDy8NzwBHuoklvdL3yM+cyJddoREe6eTco\n\
XzR7zVYAbvpqZ/VU3Mc/6aoNS+irnUK2iSIK2hZSIvX73JKZLWLtlT5DctEqRBNi\n\
qSNmRoBVRvspKDE6ZTM6AQABKSkpKDE0OmRpYmFjcnlwdC1oYXNoKDE4Okhhc2gg\n\
Q3JlYXRpb24gRGF0ZTE5OjIwMTcvMTIvMjEgMDE6MDk6MjYpKDEyOkhhc2ggVmVy\n\
c2lvbjU6MC4wLjQpKDY6S2V5IElEMzI6TjRFeTNUdm5XcWxNSXE5RnlJa0pKL2dp\n\
NXJaUG1pekwpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgxMTpQdWJsaWMg\n\
SGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lLbDdEWFVSa3RP\n\
YlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlByaXZhdGUgSGFz\n\
aDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxadGxZUlpVR1U9\n\
KSg5OkluZm8gSGFzaDQ0Ok5qd2dtZDJiVVdxaHZha0VSNER0ZHhQa21QT3hOSXhQ\n\
YmhocW5icDNqeEk9KSkA\n\
-----END DIGIBANK RSA PUBLIC KEY-----\n\
";

char mypkey[] = "\
-----BEGIN DIGIBANK RSA COMPOSITE KEY-----\n\
KDEzOmRpYmFjcnlwdC1rZXkoMTc6S2V5IENyZWF0aW9uIERhdGUxOToyMDE3LzEy\n\
LzIxIDAxOjA5OjI2KSgxMTpLZXkgVmVyc2lvbjU6MC4wLjQpKDg6S2V5IE5hbWUx\n\
MTp1bm5hbWVkIGtleSkoODpLZXkgVHlwZTM6UlNBKSgxNTpLZXkgRGVzY3JpcHRp\n\
b24xNDpubyBkZXNjcmlwdGlvbikoNjpLZXkgSUQzMjpONEV5M1R2bldxbE1JcTlG\n\
eUlrSkovZ2k1clpQbWl6TCkoMTE6S2V5IENyZWF0b3I5OnBldGVyZ2xlbikoMTI6\n\
S2V5IEhvc3RuYW1lMzpIUDIpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgx\n\
MTpQdWJsaWMgSGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lL\n\
bDdEWFVSa3RPYlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlBy\n\
aXZhdGUgSGFzaDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxa\n\
dGxZUlpVR1U9KSkoMTU6cHJpdmF0ZS1jcnlwdGVkMTI4NzrGvXOqqnAaa7uCQaF8\n\
lHiBL6lux9it2iMnzxdonXwQd/xfUBHk6dJMdgJfyftX7Z1s/ff+/CxkvsKAdVdJ\n\
YmFny2CO5lraaNZjnB/9T/qmA9njCxxBzcpTRXUufggOEXzKnUtyHVvO89dhndaB\n\
5iBmyWC9PU46doK1j7FSDp3Wt8QXzF8RwMP7YSM7+6zNmLoOOU1BOOmQfaq/449S\n\
Sp5NyJguD2wCS4mw9oJQ8Q5cnSUZZgH7u9Mma/U8ew4sK9JXRq/FFGIVp+OH+0Jm\n\
hZjm7nx+G3llV0f/+It9XTVyPdVdUl6Zv0ziRZQ+gwr7SSRh6rYT7wLGYElpp1Nk\n\
1nk2o5/aisrg8dWUStG96N2356x5SxTbs4N6cSX26YtnGP2CWKnE9Yfq6v6Zsc2F\n\
no64IT3TD9SDwk4MD1qELJUwnSP1H7lH9xybza9r2ig2lRqwMh2iIOkUoZzktJoj\n\
V43OmK9AQWMu5FiF3MZ+z8Q4LlY/fbh5W46p2eejpfNcgrGSrEhJJ9tgzr7w367Y\n\
tUnU0qtgG1nGqRrhSjTbVL8mMS2h1LXEELPqkLiPWynbDXLNUYp8WlVQWWkuhT5K\n\
5KmQArp4Jo0MBKGd+K1ceWKn+DDgz4mVwB6u0b1LKjqGpl1+ZWmVHW+J/J9N0vNI\n\
Fhh4Ewr5xUOFGMhyeonEdzl6n6ZRzgwe6bltupur4vAm7n4fvkgGmwtUwxeCgXcI\n\
ug9vb+n6Bbc2aLx+q5gWf7CAec1CrUll0kZP9B/E1DUc3qEdplcOuU5qMsrBdBog\n\
yjzi2hmpvnwzPncaARuyOi0DiZbi03AtaqOJRQRWO8nVZvPmB5LnDr/QNRtzAp8W\n\
ePC6pCVJ1XjXZVkk6UrnCoaiQrfjxULMCk8OIboohTKjmSnUE/T+MK1T19NT7oJ7\n\
d9xcB7qlTK5uqq1DZ1wo5fm9dyWWzMkkgs8S2U3EgQfInQjZcRzxNk60IQvGq7Km\n\
tKiR5cFhJ5Ud0G8KbDusGl/oNFexUagBTi4EygXqcq8cfMftqhbxha2P0lqTXELT\n\
WnYbbKuu7AsCDC+i7tNBFn00XeuF9eGFi8VxvHl5zLDS36/YIklkJIlkimZRFnNl\n\
7wE6OYz+nNMnNrq9UNmCfhWGxBO6pfmFdiTssUIRCpQH7tnEe45w49PhbmC0w7Tu\n\
n8lhIsBKhtrTRRG+4uUs3Vmq9GAgUkd8yTFoNNF/V3ymjQTW0PgYtMt5CN+CXeI0\n\
ZSrRgMrCMBB/A+HEjePpCpI+alch6mUUMS6J8hUY9NOhhRp/Fwn15s0fRhUSusFM\n\
jrx/mZwLwtTDzs++NHllI4ayFih1FHiEkDyPxXBJmBVo6r4zz68RnPrOFfprkcub\n\
NSQKDQY8qeS2U5E7x2ofw1vjO5lXMOuJbJWtg1xNT/86r5i3vPaW7eSqQz7GwcdL\n\
PS58VOQNuSaQYXTBXGOvUj7+iOHtrtR2gc64s6EM/Yja68/mqL8JlWpsTAYXsbc/\n\
fJWiSva6uIOgubRy3CRVqX+VR/6k65L0Z3pj0cbSSNV6bVXw6fKuqxzXQL7A9YdO\n\
SidNNv/95l25yjQ8TM2y2bOmqonWr/P8Bv3DKKLUkvSK56puo8474deAC6oeyknC\n\
UHokH+pI+Q+C9GAmsuFWJnLrUP6cLWignZn0EGSf+qKfGsTa9sgwrJyKycyyoO1S\n\
wBCDiFtG9O81pFy4hlDfhPY08wJOM4Wi9TUpKDE0OmRpYmFjcnlwdC1oYXNoKDE4\n\
Okhhc2ggQ3JlYXRpb24gRGF0ZTE5OjIwMTcvMTIvMjEgMDE6MDk6MjYpKDEyOkhh\n\
c2ggVmVyc2lvbjU6MC4wLjQpKDY6S2V5IElEMzI6TjRFeTNUdm5XcWxNSXE5RnlJ\n\
a0pKL2dpNXJaUG1pekwpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgxMTpQ\n\
dWJsaWMgSGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lLbDdE\n\
WFVSa3RPYlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlByaXZh\n\
dGUgSGFzaDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxadGxZ\n\
UlpVR1U9KSg5OkluZm8gSGFzaDQ0Ok5qd2dtZDJiVVdxaHZha0VSNER0ZHhQa21Q\n\
T3hOSXhQYmhocW5icDNqeEk9KSk=\n\
-----END DIGIBANK RSA COMPOSITE KEY-----\n\
";

// EOF



