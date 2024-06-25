from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

net.setLogLevel('INFO')

net.addP4Switch('s1')
net.setP4Source('s1', 'inle.p4')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')

net.addLink('h1', 's1')
net.addLink('h2', 's1')
net.addLink('h3', 's1')

net.l2()

net.enablePcapDumpAll()
net.enableLogAll()

net.startNetwork()
