import query

class IPCQuery(query.Query):
    '''
    Produce the IPC graph starting from a list of write infos
    '''
    def __init__(self, runtime_info, write_infos):
        query.Query.__init__(self, runtime_info, write_infos, linkages=[])
        self.write_infos = write_infos

    def lookup_reads(self, group_id, pid):
        self.rldb.init_cursor()
        links = self.rldb.lookup_ipc_reads(group_id, pid)
        self.rldb.close_cursor()

    def run_ipc_query(self):
        '''
        1) Find all reads from a node
        2) Look up all the sourcing IPC writes
        3) Repeat
        '''
        queue = []
        while queue:
            node = queue.pop()

class AllIPCQuery(query.Query):
    '''
    Produce the entire IPC graph
    '''
    def __init__(self, runtime_info, write_infos):
        query.Query.__init__(self, runtime_info, write_infos, linkages=[])

    def run_all_ipc_query(self):
        self.rldb.init_cursor()
        links = self.rldb.get_entire_graph()
        self.rldb.close_cursor()

        replays = self.rldb.get_all_replays()
        for (_, group_id, pid, parent_id, program, args) in replays:
            if not self.graph.has_node(group_id, pid):
                self.graph.add_node(group_id, pid, cmd=program + args)
                if self.runtime_info.verbose:
                    print("Added node (%d, %d)" % (group_id, pid))

        assert(self.graph)
        for (read_info, write_info) in links.iteritems():
            read_node = self.add_node_to_graph(read_info, "READ")
            assert (read_node)
            write_node = self.add_node_to_graph(write_info, "WRITE")
            assert (write_node)

            for node in self.graph.nodes:
                if node == write_node and not node.has_edge(read_node):
                    # add an edge from the write to the read
                    write_node.add_edge(read_node, write_info, read_info, edge_type="RW")

            for node in self.graph.nodes:
                parent_id = self.rldb.get_parent_id(node.group_id)
                if not parent_id or not node.group_id != parent_id:
                    continue
                for pnode in self.graph.nodes:
                    if pnode.group_id == parent_id and not pnode.has_edge(node):
                        pnode.add_edge(node, None, None, edge_type="EXEC")
