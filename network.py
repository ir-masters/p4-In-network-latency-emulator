from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

net.setLogLevel('INFO')

net.addP4Switch('s1')
net.setP4Source('s1', 'inle.p4')

net.addHost('h1')
net.addHost('h2')

net.addLink('s1', 'h1')
net.addLink('s1', 'h2')


net.l2()

net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()
net.startNetwork()
