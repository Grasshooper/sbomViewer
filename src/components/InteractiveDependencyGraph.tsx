import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { SBOMData, Component } from '../types/sbom';
import { 
  Search, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Download, 
  Filter,
  Maximize2,
  Settings,
  AlertTriangle,
  Shield,
  Package,
  Layers,
  Code,
  FileText
} from 'lucide-react';

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  name: string;
  version?: string;
  type: string;
  component: Component;
  dependencyCount: number;
  vulnerabilityLevel: 'none' | 'low' | 'medium' | 'high';
  radius: number;
  color: string;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
  type: 'direct' | 'transitive';
  weight: number;
}

interface InteractiveDependencyGraphProps {
  sbomData: SBOMData;
}

export function InteractiveDependencyGraph({ sbomData }: InteractiveDependencyGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(new Set());
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'library' | 'framework' | 'application'>('all');
  const [showVulnerabilities, setShowVulnerabilities] = useState(false);
  const [layoutType, setLayoutType] = useState<'force' | 'hierarchical' | 'circular'>('force');
  const [maxDepth, setMaxDepth] = useState(3);
  const [selectedComponent, setSelectedComponent] = useState<Component | null>(null);

  // Process SBOM data into graph format
  const graphData = useMemo(() => {
    if (!sbomData.components || !sbomData.dependencies) {
      return { nodes: [], links: [] };
    }

    const componentMap = new Map<string, Component>();
    sbomData.components.forEach(comp => {
      componentMap.set(comp['bom-ref'], comp);
    });

    // Create dependency count map
    const dependencyCount = new Map<string, number>();
    sbomData.dependencies.forEach(dep => {
      dep.dependsOn.forEach(ref => {
        dependencyCount.set(ref, (dependencyCount.get(ref) || 0) + 1);
      });
    });

    // Create nodes
    const nodes: GraphNode[] = sbomData.components
      .filter(comp => {
        if (filterType !== 'all' && comp.type !== filterType) return false;
        if (searchTerm && !comp.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
        return true;
      })
      .map(comp => {
        const depCount = dependencyCount.get(comp['bom-ref']) || 0;
        const vulnerabilityLevel = getVulnerabilityLevel(comp);
        
        return {
          id: comp['bom-ref'],
          name: comp.name,
          version: comp.version,
          type: comp.type,
          component: comp,
          dependencyCount: depCount,
          vulnerabilityLevel,
          radius: Math.max(8, Math.min(25, 8 + depCount * 2)),
          color: getNodeColor(comp.type, vulnerabilityLevel),
        };
      });

    const nodeIds = new Set(nodes.map(n => n.id));

    // Create links
    const links: GraphLink[] = [];
    sbomData.dependencies.forEach(dep => {
      if (!nodeIds.has(dep.ref)) return;
      
      dep.dependsOn.forEach(targetRef => {
        if (!nodeIds.has(targetRef)) return;
        
        links.push({
          source: dep.ref,
          target: targetRef,
          type: 'direct',
          weight: 1,
        });
      });
    });

    return { nodes, links };
  }, [sbomData, filterType, searchTerm, showVulnerabilities]);

  // Initialize D3 visualization
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || graphData.nodes.length === 0) return;

    const container = containerRef.current;
    const svg = d3.select(svgRef.current);
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Clear previous content
    svg.selectAll('*').remove();

    // Set up SVG
    svg.attr('width', width).attr('height', height);

    // Create zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Main group for all graph elements
    const g = svg.append('g');

    // Create arrow markers for directed edges
    svg.append('defs').selectAll('marker')
      .data(['direct', 'transitive'])
      .enter().append('marker')
      .attr('id', d => `arrow-${d}`)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 15)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', d => d === 'direct' ? '#6B7280' : '#9CA3AF');

    // Create simulation
    const simulation = d3.forceSimulation<GraphNode>(graphData.nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(graphData.links)
        .id(d => d.id)
        .distance(80)
        .strength(0.5))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => d.radius + 5));

    // Apply layout-specific forces
    if (layoutType === 'hierarchical') {
      simulation.force('y', d3.forceY().y(d => {
        const level = getNodeLevel(d.id, graphData.links);
        return 100 + level * 120;
      }).strength(0.8));
    } else if (layoutType === 'circular') {
      simulation.force('radial', d3.forceRadial(200, width / 2, height / 2).strength(0.5));
    }

    // Create links
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(graphData.links)
      .enter().append('line')
      .attr('stroke', '#9CA3AF')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', d => Math.sqrt(d.weight) * 2)
      .attr('marker-end', d => `url(#arrow-${d.type})`);

    // Create nodes
    const node = g.append('g')
      .attr('class', 'nodes')
      .selectAll('g')
      .data(graphData.nodes)
      .enter().append('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(d3.drag<SVGGElement, GraphNode>()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));

    // Add circles for nodes
    node.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => d.color)
      .attr('stroke', d => {
        if (d.vulnerabilityLevel === 'high') return '#DC2626';
        if (d.vulnerabilityLevel === 'medium') return '#F59E0B';
        if (d.vulnerabilityLevel === 'low') return '#EAB308';
        return '#E5E7EB';
      })
      .attr('stroke-width', d => d.vulnerabilityLevel !== 'none' ? 3 : 1);

    // Add labels
    node.append('text')
      .text(d => d.name.length > 15 ? d.name.substring(0, 15) + '...' : d.name)
      .attr('x', 0)
      .attr('y', d => d.radius + 15)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('font-weight', '500')
      .attr('fill', '#374151');

    // Add version labels
    node.append('text')
      .text(d => d.version || '')
      .attr('x', 0)
      .attr('y', d => d.radius + 27)
      .attr('text-anchor', 'middle')
      .attr('font-size', '8px')
      .attr('fill', '#6B7280');

    // Add type icons
    node.append('text')
      .text(d => getTypeIcon(d.type))
      .attr('x', 0)
      .attr('y', 4)
      .attr('text-anchor', 'middle')
      .attr('font-size', '12px')
      .attr('fill', 'white');

    // Node interactions
    node
      .on('click', (event, d) => {
        event.stopPropagation();
        handleNodeClick(d);
      })
      .on('dblclick', (event, d) => {
        event.stopPropagation();
        handleNodeDoubleClick(d);
      })
      .on('mouseover', (event, d) => {
        showTooltip(event, d);
        highlightConnections(d.id, true);
      })
      .on('mouseout', (event, d) => {
        hideTooltip();
        highlightConnections(d.id, false);
      });

    // Update positions on simulation tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as GraphNode).x!)
        .attr('y1', d => (d.source as GraphNode).y!)
        .attr('x2', d => (d.target as GraphNode).x!)
        .attr('y2', d => (d.target as GraphNode).y!);

      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragstarted(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>, d: GraphNode) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>, d: GraphNode) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>, d: GraphNode) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    // Helper functions
    function handleNodeClick(d: GraphNode) {
      const newSelected = new Set(selectedNodes);
      if (newSelected.has(d.id)) {
        newSelected.delete(d.id);
      } else {
        newSelected.add(d.id);
      }
      setSelectedNodes(newSelected);
      setSelectedComponent(d.component);
      
      // Update visual selection
      node.select('circle')
        .attr('stroke-width', n => {
          if (newSelected.has(n.id)) return 4;
          if (n.vulnerabilityLevel !== 'none') return 3;
          return 1;
        })
        .attr('stroke', n => {
          if (newSelected.has(n.id)) return '#2563EB';
          if (n.vulnerabilityLevel === 'high') return '#DC2626';
          if (n.vulnerabilityLevel === 'medium') return '#F59E0B';
          if (n.vulnerabilityLevel === 'low') return '#EAB308';
          return '#E5E7EB';
        });
    }

    function handleNodeDoubleClick(d: GraphNode) {
      // Center on node
      const transform = d3.zoomIdentity
        .translate(width / 2 - d.x!, height / 2 - d.y!)
        .scale(1.5);
      
      svg.transition()
        .duration(750)
        .call(zoom.transform, transform);
    }

    function highlightConnections(nodeId: string, highlight: boolean) {
      const connectedLinks = graphData.links.filter(l => 
        (typeof l.source === 'string' ? l.source : l.source.id) === nodeId ||
        (typeof l.target === 'string' ? l.target : l.target.id) === nodeId
      );
      
      const connectedNodeIds = new Set<string>();
      connectedLinks.forEach(l => {
        const sourceId = typeof l.source === 'string' ? l.source : l.source.id;
        const targetId = typeof l.target === 'string' ? l.target : l.target.id;
        connectedNodeIds.add(sourceId);
        connectedNodeIds.add(targetId);
      });

      // Highlight connected links
      link.attr('stroke-opacity', l => {
        const sourceId = typeof l.source === 'string' ? l.source : l.source.id;
        const targetId = typeof l.target === 'string' ? l.target : l.target.id;
        const isConnected = sourceId === nodeId || targetId === nodeId;
        return highlight && isConnected ? 1 : 0.6;
      })
      .attr('stroke-width', l => {
        const sourceId = typeof l.source === 'string' ? l.source : l.source.id;
        const targetId = typeof l.target === 'string' ? l.target : l.target.id;
        const isConnected = sourceId === nodeId || targetId === nodeId;
        return highlight && isConnected ? Math.sqrt(l.weight) * 3 : Math.sqrt(l.weight) * 2;
      });

      // Highlight connected nodes
      node.select('circle')
        .attr('opacity', n => {
          if (!highlight) return 1;
          return connectedNodeIds.has(n.id) ? 1 : 0.3;
        });
    }

    function showTooltip(event: MouseEvent, d: GraphNode) {
      const tooltip = d3.select('body').append('div')
        .attr('class', 'graph-tooltip')
        .style('position', 'absolute')
        .style('background', 'rgba(0, 0, 0, 0.9)')
        .style('color', 'white')
        .style('padding', '8px 12px')
        .style('border-radius', '6px')
        .style('font-size', '12px')
        .style('pointer-events', 'none')
        .style('z-index', '1000')
        .style('opacity', 0);

      tooltip.html(`
        <div><strong>${d.name}</strong></div>
        <div>Version: ${d.version || 'N/A'}</div>
        <div>Type: ${d.type}</div>
        <div>Dependencies: ${d.dependencyCount}</div>
        ${d.vulnerabilityLevel !== 'none' ? `<div style="color: #FCA5A5;">Risk: ${d.vulnerabilityLevel}</div>` : ''}
      `)
      .style('left', (event.pageX + 10) + 'px')
      .style('top', (event.pageY - 10) + 'px')
      .transition()
      .duration(200)
      .style('opacity', 1);
    }

    function hideTooltip() {
      d3.selectAll('.graph-tooltip').remove();
    }

    // Cleanup function
    return () => {
      simulation.stop();
      d3.selectAll('.graph-tooltip').remove();
    };
  }, [graphData, layoutType, selectedNodes]);

  // Helper functions
  function getVulnerabilityLevel(component: Component): 'none' | 'low' | 'medium' | 'high' {
    // Simple heuristic based on component age and type
    if (!component.version) return 'medium';
    
    const version = component.version;
    if (version.startsWith('0.') || version.startsWith('1.')) return 'medium';
    if (component.type === 'application') return 'low';
    
    return 'none';
  }

  function getNodeColor(type: string, vulnerabilityLevel: string): string {
    if (vulnerabilityLevel === 'high') return '#FCA5A5';
    if (vulnerabilityLevel === 'medium') return '#FDE68A';
    if (vulnerabilityLevel === 'low') return '#FEF3C7';
    
    switch (type) {
      case 'framework': return '#F59E0B';
      case 'library': return '#10B981';
      case 'application': return '#8B5CF6';
      default: return '#6B7280';
    }
  }

  function getTypeIcon(type: string): string {
    switch (type) {
      case 'framework': return '⚡';
      case 'library': return '📦';
      case 'application': return '🚀';
      default: return '📄';
    }
  }

  function getNodeLevel(nodeId: string, links: GraphLink[]): number {
    // Simple BFS to find node level
    const visited = new Set<string>();
    const queue: { id: string; level: number }[] = [{ id: nodeId, level: 0 }];
    
    while (queue.length > 0) {
      const { id, level } = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      
      const dependencies = links.filter(l => 
        (typeof l.source === 'string' ? l.source : l.source.id) === id
      );
      
      if (dependencies.length === 0) return level;
      
      dependencies.forEach(dep => {
        const targetId = typeof dep.target === 'string' ? dep.target : dep.target.id;
        queue.push({ id: targetId, level: level + 1 });
      });
    }
    
    return 0;
  }

  function handleZoomIn() {
    const svg = d3.select(svgRef.current);
    svg.transition().call(
      d3.zoom<SVGSVGElement, unknown>().scaleBy as any,
      1.5
    );
  }

  function handleZoomOut() {
    const svg = d3.select(svgRef.current);
    svg.transition().call(
      d3.zoom<SVGSVGElement, unknown>().scaleBy as any,
      1 / 1.5
    );
  }

  function handleResetView() {
    const svg = d3.select(svgRef.current);
    svg.transition().call(
      d3.zoom<SVGSVGElement, unknown>().transform as any,
      d3.zoomIdentity
    );
  }

  function handleFitToScreen() {
    if (!containerRef.current) return;
    
    const svg = d3.select(svgRef.current);
    const bounds = svg.select('g').node()?.getBBox();
    if (!bounds) return;

    const width = containerRef.current.clientWidth;
    const height = containerRef.current.clientHeight;
    const scale = Math.min(width / bounds.width, height / bounds.height) * 0.9;
    
    const transform = d3.zoomIdentity
      .translate(width / 2 - bounds.x * scale - bounds.width * scale / 2, 
                height / 2 - bounds.y * scale - bounds.height * scale / 2)
      .scale(scale);
    
    svg.transition().duration(750).call(
      d3.zoom<SVGSVGElement, unknown>().transform as any,
      transform
    );
  }

  function exportGraph() {
    if (!svgRef.current) return;
    
    const svgElement = svgRef.current;
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svgElement);
    const blob = new Blob([svgString], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = 'dependency-graph.svg';
    link.click();
    
    URL.revokeObjectURL(url);
  }

  const stats = useMemo(() => {
    return {
      totalNodes: graphData.nodes.length,
      totalLinks: graphData.links.length,
      vulnerableNodes: graphData.nodes.filter(n => n.vulnerabilityLevel !== 'none').length,
      isolatedNodes: graphData.nodes.filter(n => n.dependencyCount === 0).length,
    };
  }, [graphData]);

  if (!sbomData.components || !sbomData.dependencies) {
    return (
      <div className="bg-white rounded-xl shadow-sm p-8 text-center">
        <Package className="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No Dependency Data</h3>
        <p className="text-gray-600">This SBOM doesn't contain dependency information required for graph visualization.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Controls Panel */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <div className="flex flex-wrap items-center gap-4 mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Interactive Dependency Graph</h2>
          
          {/* Search */}
          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search components..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>

          {/* Filter Type */}
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as any)}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          >
            <option value="all">All Types</option>
            <option value="framework">Frameworks</option>
            <option value="library">Libraries</option>
            <option value="application">Applications</option>
          </select>

          {/* Layout Type */}
          <select
            value={layoutType}
            onChange={(e) => setLayoutType(e.target.value as any)}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          >
            <option value="force">Force Layout</option>
            <option value="hierarchical">Hierarchical</option>
            <option value="circular">Circular</option>
          </select>

          {/* Vulnerability Filter */}
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={showVulnerabilities}
              onChange={(e) => setShowVulnerabilities(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            Show Vulnerabilities
          </label>
        </div>

        {/* Zoom Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleZoomIn}
            className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          
          <button
            onClick={handleZoomOut}
            className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          
          <button
            onClick={handleResetView}
            className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            title="Reset View"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
          
          <button
            onClick={handleFitToScreen}
            className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            title="Fit to Screen"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          
          <button
            onClick={exportGraph}
            className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            title="Export Graph"
          >
            <Download className="w-4 h-4" />
          </button>

          {/* Stats */}
          <div className="ml-auto flex items-center gap-4 text-sm text-gray-600">
            <span>{stats.totalNodes} nodes</span>
            <span>{stats.totalLinks} connections</span>
            {stats.vulnerableNodes > 0 && (
              <span className="text-red-600">{stats.vulnerableNodes} vulnerable</span>
            )}
          </div>
        </div>
      </div>

      {/* Graph Container */}
      <div className="bg-white rounded-xl shadow-sm overflow-hidden">
        <div className="flex">
          {/* Main Graph */}
          <div 
            ref={containerRef}
            className="flex-1 relative"
            style={{ height: '600px' }}
          >
            <svg
              ref={svgRef}
              className="w-full h-full border border-gray-200"
              style={{ background: '#FAFAFA' }}
            />
            
            {/* Legend */}
            <div className="absolute top-4 right-4 bg-white rounded-lg shadow-lg p-4 max-w-xs">
              <h4 className="font-medium text-gray-900 mb-3">Legend</h4>
              
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-emerald-500"></div>
                  <span>Library</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-amber-500"></div>
                  <span>Framework</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-purple-500"></div>
                  <span>Application</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-gray-400"></div>
                  <span>Other</span>
                </div>
                
                <hr className="my-2" />
                
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-red-200 border-2 border-red-600"></div>
                  <span>High Risk</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-yellow-200 border-2 border-yellow-600"></div>
                  <span>Medium Risk</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-blue-200 border-2 border-blue-600"></div>
                  <span>Selected</span>
                </div>
              </div>
              
              <div className="mt-3 pt-3 border-t border-gray-200 text-xs text-gray-500">
                <p>• Node size = dependency count</p>
                <p>• Click to select, double-click to center</p>
                <p>• Drag to reposition nodes</p>
                <p>• Hover for details</p>
              </div>
            </div>
          </div>

          {/* Side Panel */}
          {selectedComponent && (
            <div className="w-80 border-l border-gray-200 p-6 bg-gray-50 overflow-y-auto" style={{ height: '600px' }}>
              <div className="space-y-4">
                <div>
                  <h3 className="font-semibold text-gray-900 mb-2">Selected Component</h3>
                  <div className="bg-white rounded-lg p-4 space-y-2">
                    <div className="flex items-center gap-2">
                      {selectedComponent.type === 'framework' && <Layers className="w-4 h-4 text-amber-600" />}
                      {selectedComponent.type === 'library' && <Package className="w-4 h-4 text-emerald-600" />}
                      {selectedComponent.type === 'application' && <Code className="w-4 h-4 text-purple-600" />}
                      {!['framework', 'library', 'application'].includes(selectedComponent.type) && <FileText className="w-4 h-4 text-gray-600" />}
                      <span className="font-medium">{selectedComponent.name}</span>
                    </div>
                    
                    {selectedComponent.version && (
                      <p className="text-sm text-gray-600">Version: {selectedComponent.version}</p>
                    )}
                    
                    <p className="text-sm text-gray-600 capitalize">Type: {selectedComponent.type}</p>
                    
                    {selectedComponent.description && (
                      <p className="text-sm text-gray-600">{selectedComponent.description}</p>
                    )}
                  </div>
                </div>

                {/* Dependencies */}
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Dependencies</h4>
                  <div className="bg-white rounded-lg p-4">
                    {(() => {
                      const deps = sbomData.dependencies?.find(d => d.ref === selectedComponent['bom-ref']);
                      if (!deps || deps.dependsOn.length === 0) {
                        return <p className="text-sm text-gray-500">No dependencies</p>;
                      }
                      
                      return (
                        <div className="space-y-2">
                          {deps.dependsOn.slice(0, 5).map((depRef, index) => {
                            const depComponent = sbomData.components?.find(c => c['bom-ref'] === depRef);
                            return depComponent ? (
                              <div key={index} className="text-sm p-2 bg-gray-50 rounded">
                                <p className="font-medium">{depComponent.name}</p>
                                <p className="text-gray-600">{depComponent.version}</p>
                              </div>
                            ) : null;
                          })}
                          {deps.dependsOn.length > 5 && (
                            <p className="text-xs text-gray-500">
                              ... and {deps.dependsOn.length - 5} more
                            </p>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                </div>

                {/* Licenses */}
                {selectedComponent.licenses && selectedComponent.licenses.length > 0 && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Licenses</h4>
                    <div className="bg-white rounded-lg p-4 space-y-1">
                      {selectedComponent.licenses.map((license, index) => (
                        <div key={index} className="text-sm p-2 bg-emerald-50 rounded flex items-center gap-2">
                          <Shield className="w-3 h-3 text-emerald-600" />
                          <span>{license.license?.name || license.license?.id || 'Unknown'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Security Hashes */}
                {selectedComponent.hashes && selectedComponent.hashes.length > 0 && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Security Hashes</h4>
                    <div className="bg-white rounded-lg p-4 space-y-2">
                      {selectedComponent.hashes.slice(0, 2).map((hash, index) => (
                        <div key={index} className="text-xs">
                          <p className="font-medium text-gray-700">{hash.alg}</p>
                          <p className="font-mono text-gray-600 break-all">{hash.content.substring(0, 32)}...</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Graph Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-xl shadow-sm p-6 text-center">
          <Package className="w-8 h-8 text-blue-600 mx-auto mb-2" />
          <p className="text-2xl font-bold text-gray-900">{stats.totalNodes}</p>
          <p className="text-sm text-gray-600">Components</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm p-6 text-center">
          <div className="w-8 h-8 mx-auto mb-2 flex items-center justify-center">
            <div className="w-6 h-0.5 bg-gray-600"></div>
          </div>
          <p className="text-2xl font-bold text-gray-900">{stats.totalLinks}</p>
          <p className="text-sm text-gray-600">Dependencies</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm p-6 text-center">
          <AlertTriangle className="w-8 h-8 text-red-600 mx-auto mb-2" />
          <p className="text-2xl font-bold text-gray-900">{stats.vulnerableNodes}</p>
          <p className="text-sm text-gray-600">At Risk</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm p-6 text-center">
          <div className="w-8 h-8 text-gray-400 mx-auto mb-2 flex items-center justify-center">
            <div className="w-4 h-4 rounded-full bg-gray-400"></div>
          </div>
          <p className="text-2xl font-bold text-gray-900">{stats.isolatedNodes}</p>
          <p className="text-sm text-gray-600">Isolated</p>
        </div>
      </div>

      {/* Instructions */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
        <div className="flex items-start gap-3">
          <Settings className="w-5 h-5 text-blue-600 mt-0.5" />
          <div>
            <h3 className="text-lg font-semibold text-blue-900 mb-2">How to Use the Dependency Graph</h3>
            <ul className="space-y-1 text-sm text-blue-800">
              <li>• <strong>Navigate:</strong> Pan by dragging empty space, zoom with mouse wheel</li>
              <li>• <strong>Select:</strong> Click nodes to view details in the side panel</li>
              <li>• <strong>Focus:</strong> Double-click a node to center and zoom to it</li>
              <li>• <strong>Explore:</strong> Hover over nodes to see immediate connections</li>
              <li>• <strong>Reposition:</strong> Drag nodes to manually arrange the layout</li>
              <li>• <strong>Filter:</strong> Use search and type filters to focus on specific components</li>
              <li>• <strong>Export:</strong> Save the current graph view as an SVG file</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}