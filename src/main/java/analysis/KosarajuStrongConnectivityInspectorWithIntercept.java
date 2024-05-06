package analysis;

import org.jgrapht.Graph;
import org.jgrapht.alg.connectivity.KosarajuStrongConnectivityInspector;
import org.jgrapht.graph.AsSubgraph;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class KosarajuStrongConnectivityInspectorWithIntercept<V, E> extends KosarajuStrongConnectivityInspector<V, E> {

    public KosarajuStrongConnectivityInspectorWithIntercept(Graph<V, E> graph) {
        super(graph);
    }

    @Override
    public List<Graph<V, E>> getStronglyConnectedComponents() {
        if (this.stronglyConnectedSubgraphs == null) {
            List<Set<V>> sets = this.stronglyConnectedSets();
            this.stronglyConnectedSubgraphs = new ArrayList<>(sets.size());

            for (Set<V> set : sets) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new RuntimeException(new InterruptedException());
                }
                this.stronglyConnectedSubgraphs.add(new AsSubgraph<>(this.graph, set, null));
            }
        }

        return this.stronglyConnectedSubgraphs;
    }
}
