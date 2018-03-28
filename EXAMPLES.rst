========
EXAMPLES
========

In this example, we will emulate the first inform message ``1 BOOT`` of 100
devices to ACS server at IP 10.72.110.79 with a total of 20 calls each. The
user think-time between call bursts would be 0.5 second. The emulate device
will have the serial number in template of EMUL0000001 to EMUL0000100:

.. code-block:: bash

    httperf --timeout=60 --client=0/1 --server=10.72.110.79 --port=7547 --uri=/ --rate=5 --send-buffer=4096 --retry-on-failure --recv-buffer=16384 --session-cookies --add-header='Content-type: text/xml; charset="utf-8"\nSOAPAction:\n' --num-conns=1 --num-calls=1 --cwmp=100,0.5,/etc/httperf/tr069_first_inform_full,EMUL


