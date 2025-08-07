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
  FileText,
  Target,
  GitBranch,
  Zap,
  Eye,
  EyeOff,
  Lock,
  Unlock,
  RefreshCw,
  BarChart3,
  Network,
  Compass
} from 'lucide-react';

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  name: string;
  version?: string;
  type: string;
  component: Component;
  dependencyCount: number;
  dependentCount: number;
  vulnerabilityLevel: 'none' | 'low' | 'medium' | 'high';
  radius: number;
  color: string;
  level: number;
  cluster: number;
  isOrphan: boolean;
  criticalityScore: number;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
  type: 'direct' | 'transitive';
  weight: number;
  isCircular: boolean;
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
  const [layoutType, setLayoutType] = useState<'force' | 'hierarchical' | 'circular' | 'clustered'>('hierarchical');
  const [maxDepth, setMaxDepth] = useState(3);
  const [selectedComponent, setSelectedComponent] = useState<Component | null>(null);
  const [showOrphans, setShowOrphans] = useState(true);
  const [showTransitive, setShowTransitive] = useState(false);
  const [minCriticality, setMinCriticality] = useState(0);
  const [highlightPath, setHighlightPath] = useState<string[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Process SBOM data into graph format with enhanced analysis
  const graphData = useMemo(() => {
    if (!sbomData.components || !sbomData.dependencies) {
      return { nodes: [], links: [], clusters: [], circularDeps: [], criticalPath: [] };
    }

    const componentMap = new Map<string, Component>();
    sbomData.components.forEach(comp => {
      componentMap.set(comp['bom-ref'], comp);
    });

    // Build dependency maps
    const dependencyCount = new Map<string, number>();
    const dependentCount = new Map<string, number>();
    const allConnections = new Set<string>();

    sbomData.dependencies.forEach(dep => {
      dependentCount.set(dep.ref, (dependentCount.get(dep.ref) || 0) + dep.dependsOn.length);
      dep.dependsOn.forEach(ref => {
        dependencyCount.set(ref, (dependencyCount.get(ref) || 0) + 1);
        allConnections.add(dep.ref);
        allConnections.add(ref);
      });
    });

    // Calculate component levels and clusters
    const componentLevels = calculateComponentLevels(sbomData.dependencies);
    const clusters = detectClusters(sbomData.dependencies, componentMap);

    // Create nodes with enhanced metadata
    const nodes: GraphNode[] = sbomData.components
      .filter(comp => {
        if (filterType !== 'all' && comp.type !== filterType) return false;
        if (searchTerm && !comp.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
        if (!showOrphans && !allConnections.has(comp['bom-ref'])) return false;
        return true;
      })
      .map(comp => {
        const depCount = dependencyCount.get(comp['bom-ref']) || 0;
        const dependentCnt = dependentCount.get(comp['bom-ref']) || 0;
        const vulnerabilityLevel = getVulnerabilityLevel(comp);
        const level = componentLevels.get(comp['bom-ref']) || 0;
        const cluster = clusters.get(comp['bom-ref']) || 0;
        const isOrphan = !allConnections.has(comp['bom-ref']);
        const criticalityScore = calculateCriticalityScore(comp, depCount, dependentCnt, vulnerabilityLevel);
        
        if (criticalityScore < minCriticality) return null;
        
        return {
          id: comp['bom-ref'],
          name: comp.name,
          version: comp.version,
          type: comp.type,
          component: comp,
          dependencyCount: depCount,
          dependentCount: dependentCnt,
          vulnerabilityLevel,
          radius: Math.max(8, Math.min(30, 8 + Math.sqrt(depCount + dependentCnt) * 3)),
          color: getNodeColor(comp.type, vulnerabilityLevel, isOrphan),
          level,
          cluster,
          isOrphan,
          criticalityScore,
        };
      })
      .filter(Boolean) as GraphNode[];

    const nodeIds = new Set(nodes.map(n => n.id));

    // Create links with enhanced metadata
    const links: GraphLink[] = [];
    const circularDeps: string[] = [];

    sbomData.dependencies.forEach(dep => {
      if (!nodeIds.has(dep.ref)) return;
      
      dep.dependsOn.forEach((targetRef, index) => {
        if (!nodeIds.has(targetRef)) return;
        
        // Check for circular dependencies
        const isCircular = hasCircularDependency(dep.ref, targetRef, sbomData.dependencies);
        if (isCircular) {
          circularDeps.push(`${dep.ref} -> ${targetRef}`);
        }
        
        // Skip transitive dependencies if not showing them
        if (!showTransitive && index > 2) return;
        
        links.push({
          source: dep.ref,
          target: targetRef,
          type: index === 0 ? 'direct' : 'transitive',
          weight: index === 0 ? 1 : 0.5,
          isCircular,
        });
      });
    });

    // Calculate critical path
    const criticalPath = findCriticalPath(nodes, links);

    return { 
      nodes, 
      links, 
      clusters: Array.from(clusters.values()), 
      circularDeps,
      criticalPath 
    };
  }, [sbomData, filterType, searchTerm, showOrphans, showTransitive, minCriticality]);

  // Initialize D3 visualization with improved layout
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || graphData.nodes.length === 0) return;

    const container = containerRef.current;
    const svg = d3.select(svgRef.current);
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Clear previous content
    svg.selectAll('*').remove();

    // Set up SVG with better organization
    svg.attr('width', width).attr('height', height);

    // Create zoom behavior with constraints
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 5])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Main group for all graph elements
    const g = svg.append('g');

    // Create definitions for patterns and gradients
    const defs = svg.append('defs');
    
    // Gradient for vulnerability levels
    const gradients = ['low', 'medium', 'high'].map(level => {
      const gradient = defs.append('radialGradient')
        .attr('id', `gradient-${level}`)
        .attr('cx', '30%')
        .attr('cy', '30%');
      
      gradient.append('stop')
        .attr('offset', '0%')
        .attr('stop-color', level === 'high' ? '#FCA5A5' : level === 'medium' ? '#FDE68A' : '#D1FAE5');
      
      gradient.append('stop')
        .attr('offset', '100%')
        .attr('stop-color', level === 'high' ? '#DC2626' : level === 'medium' ? '#F59E0B' : '#059669');
      
      return gradient;
    });

    // Create arrow markers with different styles
    defs.selectAll('marker')
      .data(['direct', 'transitive', 'circular'])
      .enter().append('marker')
      .attr('id', d => `arrow-${d}`)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', d => {
        if (d === 'circular') return '#DC2626';
        if (d === 'transitive') return '#9CA3AF';
        return '#374151';
      });

    // Create simulation with improved forces
    const simulation = d3.forceSimulation<GraphNode>(graphData.nodes);

    // Apply layout-specific forces
    if (layoutType === 'hierarchical') {
      simulation
        .force('link', d3.forceLink<GraphNode, GraphLink>(graphData.links)
          .id(d => d.id)
          .distance(100)
          .strength(0.3))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('x', d3.forceX(width / 2).strength(0.1))
        .force('y', d3.forceY().y(d => 80 + d.level * 120).strength(0.8))
        .force('collision', d3.forceCollide().radius(d => d.radius + 10));
    } else if (layoutType === 'circular') {
      simulation
        .force('link', d3.forceLink<GraphNode, GraphLink>(graphData.links)
          .id(d => d.id)
          .distance(80)
          .strength(0.2))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('radial', d3.forceRadial()
          .radius(d => 100 + d.level * 80)
          .x(width / 2)
          .y(height / 2)
          .strength(0.7))
        .force('collision', d3.forceCollide().radius(d => d.radius + 8));
    } else if (layoutType === 'clustered') {
      simulation
        .force('link', d3.forceLink<GraphNode, GraphLink>(graphData.links)
          .id(d => d.id)
          .distance(60)
          .strength(0.4))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('cluster', forceCluster().centers(getClusterCenters(graphData.nodes, width, height)))
        .force('collision', d3.forceCollide().radius(d => d.radius + 5));
    } else {
      // Force layout
      simulation
        .force('link', d3.forceLink<GraphNode, GraphLink>(graphData.links)
          .id(d => d.id)
          .distance(d => d.type === 'direct' ? 80 : 120)
          .strength(d => d.type === 'direct' ? 0.5 : 0.2))
        .force('charge', d3.forceManyBody().strength(-350))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.radius + 8));
    }

    // Create links with improved styling
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(graphData.links)
      .enter().append('line')
      .attr('stroke', d => {
        if (d.isCircular) return '#DC2626';
        if (d.type === 'transitive') return '#D1D5DB';
        return '#6B7280';
      })
      .attr('stroke-opacity', d => d.type === 'transitive' ? 0.3 : 0.7)
      .attr('stroke-width', d => Math.max(1, d.weight * 2))
      .attr('stroke-dasharray', d => d.type === 'transitive' ? '5,5' : 'none')
      .attr('marker-end', d => `url(#arrow-${d.isCircular ? 'circular' : d.type})`);

    // Create node groups
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

    // Add circles for nodes with enhanced styling
    node.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => {
        if (d.vulnerabilityLevel !== 'none' && showVulnerabilities) {
          return `url(#gradient-${d.vulnerabilityLevel})`;
        }
        return d.color;
      })
      .attr('stroke', d => {
        if (selectedNodes.has(d.id)) return '#2563EB';
        if (d.isOrphan) return '#F59E0B';
        if (d.vulnerabilityLevel === 'high') return '#DC2626';
        if (d.vulnerabilityLevel === 'medium') return '#F59E0B';
        if (d.vulnerabilityLevel === 'low') return '#EAB308';
        return '#E5E7EB';
      })
      .attr('stroke-width', d => {
        if (selectedNodes.has(d.id)) return 4;
        if (d.vulnerabilityLevel !== 'none') return 3;
        if (d.isOrphan) return 2;
        return 1;
      })
      .attr('opacity', d => {
        if (highlightPath.length > 0) {
          return highlightPath.includes(d.id) ? 1 : 0.3;
        }
        return 1;
      });

    // Add component type icons
    node.append('text')
      .text(d => getTypeIcon(d.type))
      .attr('x', 0)
      .attr('y', 5)
      .attr('text-anchor', 'middle')
      .attr('font-size', d => Math.min(16, d.radius * 0.8))
      .attr('fill', 'white')
      .attr('pointer-events', 'none');

    // Add vulnerability indicators
    node.filter(d => d.vulnerabilityLevel !== 'none')
      .append('circle')
      .attr('r', d => d.radius + 3)
      .attr('fill', 'none')
      .attr('stroke', d => {
        if (d.vulnerabilityLevel === 'high') return '#DC2626';
        if (d.vulnerabilityLevel === 'medium') return '#F59E0B';
        return '#EAB308';
      })
      .attr('stroke-width', 2)
      .attr('stroke-dasharray', '3,3')
      .style('animation', 'pulse 2s infinite');

    // Add criticality indicators for high-impact components
    node.filter(d => d.criticalityScore > 0.7)
      .append('polygon')
      .attr('points', d => {
        const size = 6;
        const offset = d.radius + 8;
        return `${-size},${-offset} ${size},${-offset} 0,${-offset-size}`;
      })
      .attr('fill', '#DC2626')
      .attr('stroke', 'white')
      .attr('stroke-width', 1);

    // Add labels with improved positioning
    node.append('text')
      .text(d => {
        const maxLength = Math.max(8, Math.floor(d.radius / 3));
        return d.name.length > maxLength ? d.name.substring(0, maxLength) + '...' : d.name;
      })
      .attr('x', 0)
      .attr('y', d => d.radius + 18)
      .attr('text-anchor', 'middle')
      .attr('font-size', '11px')
      .attr('font-weight', '600')
      .attr('fill', '#374151')
      .attr('pointer-events', 'none');

    // Add version labels
    node.filter(d => d.version)
      .append('text')
      .text(d => `v${d.version}`)
      .attr('x', 0)
      .attr('y', d => d.radius + 32)
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('fill', '#6B7280')
      .attr('pointer-events', 'none');

    // Add dependency count badges
    node.filter(d => d.dependencyCount > 0)
      .append('circle')
      .attr('cx', d => d.radius - 5)
      .attr('cy', d => -d.radius + 5)
      .attr('r', 8)
      .attr('fill', '#2563EB')
      .attr('stroke', 'white')
      .attr('stroke-width', 2);

    node.filter(d => d.dependencyCount > 0)
      .append('text')
      .text(d => d.dependencyCount > 99 ? '99+' : d.dependencyCount.toString())
      .attr('x', d => d.radius - 5)
      .attr('y', d => -d.radius + 9)
      .attr('text-anchor', 'middle')
      .attr('font-size', '8px')
      .attr('font-weight', 'bold')
      .attr('fill', 'white')
      .attr('pointer-events', 'none');

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
      })
      .on('contextmenu', (event, d) => {
        event.preventDefault();
        showContextMenu(event, d);
      });

    // Update positions on simulation tick
    simulation.on('tick', () => {
      // Constrain nodes to viewport
      graphData.nodes.forEach(d => {
        d.x = Math.max(d.radius, Math.min(width - d.radius, d.x || 0));
        d.y = Math.max(d.radius, Math.min(height - d.radius, d.y || 0));
      });

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
      updateNodeSelection(newSelected);
    }

    function handleNodeDoubleClick(d: GraphNode) {
      // Find and highlight path to root
      const path = findPathToRoot(d.id, graphData.links);
      setHighlightPath(path);
      
      // Center on node with animation
      const transform = d3.zoomIdentity
        .translate(width / 2 - d.x!, height / 2 - d.y!)
        .scale(1.5);
      
      svg.transition()
        .duration(750)
        .call(zoom.transform, transform);
    }

    function updateNodeSelection(selected: Set<string>) {
      node.select('circle')
        .attr('stroke-width', n => {
          if (selected.has(n.id)) return 4;
          if (n.vulnerabilityLevel !== 'none') return 3;
          if (n.isOrphan) return 2;
          return 1;
        })
        .attr('stroke', n => {
          if (selected.has(n.id)) return '#2563EB';
          if (n.isOrphan) return '#F59E0B';
          if (n.vulnerabilityLevel === 'high') return '#DC2626';
          if (n.vulnerabilityLevel === 'medium') return '#F59E0B';
          if (n.vulnerabilityLevel === 'low') return '#EAB308';
          return '#E5E7EB';
        });
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
      link
        .attr('stroke-opacity', l => {
          const sourceId = typeof l.source === 'string' ? l.source : l.source.id;
          const targetId = typeof l.target === 'string' ? l.target : l.target.id;
          const isConnected = sourceId === nodeId || targetId === nodeId;
          return highlight && isConnected ? 1 : (l.type === 'transitive' ? 0.3 : 0.7);
        })
        .attr('stroke-width', l => {
          const sourceId = typeof l.source === 'string' ? l.source : l.source.id;
          const targetId = typeof l.target === 'string' ? l.target : l.target.id;
          const isConnected = sourceId === nodeId || targetId === nodeId;
          return highlight && isConnected ? Math.max(2, l.weight * 4) : Math.max(1, l.weight * 2);
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
        .style('background', 'rgba(0, 0, 0, 0.95)')
        .style('color', 'white')
        .style('padding', '12px 16px')
        .style('border-radius', '8px')
        .style('font-size', '12px')
        .style('pointer-events', 'none')
        .style('z-index', '1000')
        .style('box-shadow', '0 4px 12px rgba(0,0,0,0.3)')
        .style('opacity', 0);

      tooltip.html(`
        <div style="margin-bottom: 8px;"><strong style="font-size: 14px;">${d.name}</strong></div>
        <div style="margin-bottom: 4px;">Version: <span style="color: #93C5FD;">${d.version || 'N/A'}</span></div>
        <div style="margin-bottom: 4px;">Type: <span style="color: #86EFAC;">${d.type}</span></div>
        <div style="margin-bottom: 4px;">Dependencies: <span style="color: #FDE68A;">${d.dependencyCount}</span></div>
        <div style="margin-bottom: 4px;">Dependents: <span style="color: #F9A8D4;">${d.dependentCount}</span></div>
        <div style="margin-bottom: 4px;">Level: <span style="color: #C4B5FD;">${d.level}</span></div>
        <div style="margin-bottom: 4px;">Criticality: <span style="color: ${d.criticalityScore > 0.7 ? '#FCA5A5' : d.criticalityScore > 0.4 ? '#FDE68A' : '#D1FAE5'}">${Math.round(d.criticalityScore * 100)}%</span></div>
        ${d.vulnerabilityLevel !== 'none' ? `<div style="color: #FCA5A5; margin-top: 8px; padding-top: 8px; border-top: 1px solid #374151;">⚠️ ${d.vulnerabilityLevel.toUpperCase()} RISK</div>` : ''}
        ${d.isOrphan ? `<div style="color: #FDE68A; margin-top: 4px;">🔸 Isolated Component</div>` : ''}
      `)
      .style('left', (event.pageX + 15) + 'px')
      .style('top', (event.pageY - 10) + 'px')
      .transition()
      .duration(200)
      .style('opacity', 1);
    }

    function hideTooltip() {
      d3.selectAll('.graph-tooltip').remove();
    }

    function showContextMenu(event: MouseEvent, d: GraphNode) {
      // Context menu for advanced actions
      const menu = d3.select('body').append('div')
        .attr('class', 'context-menu')
        .style('position', 'absolute')
        .style('background', 'white')
        .style('border', '1px solid #D1D5DB')
        .style('border-radius', '6px')
        .style('box-shadow', '0 4px 12px rgba(0,0,0,0.15)')
        .style('padding', '4px')
        .style('z-index', '1001')
        .style('left', event.pageX + 'px')
        .style('top', event.pageY + 'px');

      const menuItems = [
        { label: 'Show Dependencies', action: () => showDependencies(d.id) },
        { label: 'Show Dependents', action: () => showDependents(d.id) },
        { label: 'Find Path to Root', action: () => findAndHighlightPath(d.id) },
        { label: 'Analyze Impact', action: () => analyzeImpact(d.id) },
        { label: 'Center on Node', action: () => centerOnNode(d) },
      ];

      menuItems.forEach(item => {
        menu.append('div')
          .style('padding', '8px 12px')
          .style('cursor', 'pointer')
          .style('font-size', '12px')
          .style('border-radius', '4px')
          .text(item.label)
          .on('mouseover', function() {
            d3.select(this).style('background', '#F3F4F6');
          })
          .on('mouseout', function() {
            d3.select(this).style('background', 'white');
          })
          .on('click', () => {
            item.action();
            d3.selectAll('.context-menu').remove();
          });
      });

      // Remove menu on outside click
      d3.select('body').on('click.context-menu', () => {
        d3.selectAll('.context-menu').remove();
        d3.select('body').on('click.context-menu', null);
      });
    }

    // Advanced analysis functions
    function showDependencies(nodeId: string) {
      const deps = graphData.links
        .filter(l => (typeof l.source === 'string' ? l.source : l.source.id) === nodeId)
        .map(l => typeof l.target === 'string' ? l.target : l.target.id);
      setHighlightPath([nodeId, ...deps]);
    }

    function showDependents(nodeId: string) {
      const dependents = graphData.links
        .filter(l => (typeof l.target === 'string' ? l.target : l.target.id) === nodeId)
        .map(l => typeof l.source === 'string' ? l.source : l.source.id);
      setHighlightPath([nodeId, ...dependents]);
    }

    function findAndHighlightPath(nodeId: string) {
      const path = findPathToRoot(nodeId, graphData.links);
      setHighlightPath(path);
    }

    function analyzeImpact(nodeId: string) {
      setIsAnalyzing(true);
      // Simulate analysis delay
      setTimeout(() => {
        const impact = calculateImpactAnalysis(nodeId, graphData.links, graphData.nodes);
        setHighlightPath(impact.affectedComponents);
        setIsAnalyzing(false);
      }, 1000);
    }

    function centerOnNode(d: GraphNode) {
      const transform = d3.zoomIdentity
        .translate(width / 2 - d.x!, height / 2 - d.y!)
        .scale(1.2);
      
      svg.transition()
        .duration(500)
        .call(zoom.transform, transform);
    }

    // Cleanup function
    return () => {
      simulation.stop();
      d3.selectAll('.graph-tooltip').remove();
      d3.selectAll('.context-menu').remove();
    };
  }, [graphData, layoutType, selectedNodes, highlightPath, showVulnerabilities]);

  // Helper functions
  function getVulnerabilityLevel(component: Component): 'none' | 'low' | 'medium' | 'high' {
    // Enhanced vulnerability detection
    if (!component.version) return 'medium';
    
    const version = component.version;
    const name = component.name.toLowerCase();
    
    // Check for known vulnerable patterns
    if (name.includes('log4j') && version.startsWith('2.') && parseFloat(version.split('.')[1]) < 17) return 'high';
    if (name.includes('jackson') && version.startsWith('2.') && parseFloat(version.split('.')[1]) < 12) return 'high';
    if (name.includes('spring') && version.startsWith('4.')) return 'medium';
    if (version.startsWith('0.') || version.includes('alpha') || version.includes('beta')) return 'medium';
    if (component.type === 'application') return 'low';
    
    // Check for very old versions
    const majorVersion = parseInt(version.split('.')[0]);
    if (majorVersion < 2) return 'medium';
    
    return 'none';
  }

  function getNodeColor(type: string, vulnerabilityLevel: string, isOrphan: boolean): string {
    if (isOrphan) return '#D1D5DB';
    
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

  function calculateComponentLevels(dependencies: any[]): Map<string, number> {
    const levels = new Map<string, number>();
    const visited = new Set<string>();
    
    function dfs(nodeId: string, level: number) {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      levels.set(nodeId, Math.max(levels.get(nodeId) || 0, level));
      
      const deps = dependencies.find(d => d.ref === nodeId);
      if (deps) {
        deps.dependsOn.forEach((depId: string) => {
          dfs(depId, level + 1);
        });
      }
    }
    
    // Start from root components (those with no dependents)
    const allTargets = new Set(dependencies.flatMap(d => d.dependsOn));
    const roots = dependencies
      .map(d => d.ref)
      .filter(ref => !allTargets.has(ref));
    
    roots.forEach(root => dfs(root, 0));
    
    return levels;
  }

  function detectClusters(dependencies: any[], componentMap: Map<string, Component>): Map<string, number> {
    const clusters = new Map<string, number>();
    let clusterId = 0;
    
    // Simple clustering based on component type and common dependencies
    const typeGroups = new Map<string, string[]>();
    
    componentMap.forEach((comp, id) => {
      const type = comp.type;
      if (!typeGroups.has(type)) {
        typeGroups.set(type, []);
      }
      typeGroups.get(type)!.push(id);
    });
    
    typeGroups.forEach(components => {
      components.forEach(compId => {
        clusters.set(compId, clusterId);
      });
      clusterId++;
    });
    
    return clusters;
  }

  function calculateCriticalityScore(
    component: Component, 
    dependencyCount: number, 
    dependentCount: number, 
    vulnerabilityLevel: string
  ): number {
    let score = 0;
    
    // Base score from dependency counts
    score += Math.min(0.4, dependencyCount * 0.05);
    score += Math.min(0.4, dependentCount * 0.1);
    
    // Vulnerability impact
    if (vulnerabilityLevel === 'high') score += 0.3;
    else if (vulnerabilityLevel === 'medium') score += 0.2;
    else if (vulnerabilityLevel === 'low') score += 0.1;
    
    // Component type impact
    if (component.type === 'framework') score += 0.2;
    else if (component.type === 'application') score += 0.1;
    
    return Math.min(1, score);
  }

  function hasCircularDependency(sourceId: string, targetId: string, dependencies: any[]): boolean {
    const visited = new Set<string>();
    
    function dfs(currentId: string): boolean {
      if (currentId === sourceId) return true;
      if (visited.has(currentId)) return false;
      visited.add(currentId);
      
      const deps = dependencies.find(d => d.ref === currentId);
      if (deps) {
        return deps.dependsOn.some((depId: string) => dfs(depId));
      }
      return false;
    }
    
    return dfs(targetId);
  }

  function findPathToRoot(nodeId: string, links: GraphLink[]): string[] {
    const path: string[] = [nodeId];
    const visited = new Set<string>();
    
    function findParent(currentId: string): string | null {
      const parentLink = links.find(l => 
        (typeof l.target === 'string' ? l.target : l.target.id) === currentId
      );
      return parentLink ? (typeof parentLink.source === 'string' ? parentLink.source : parentLink.source.id) : null;
    }
    
    let current = nodeId;
    while (current && !visited.has(current)) {
      visited.add(current);
      const parent = findParent(current);
      if (parent) {
        path.unshift(parent);
        current = parent;
      } else {
        break;
      }
    }
    
    return path;
  }

  function findCriticalPath(nodes: GraphNode[], links: GraphLink[]): string[] {
    // Find the path with highest cumulative criticality score
    const paths: string[][] = [];
    
    nodes.forEach(node => {
      if (node.level === 0) { // Start from root nodes
        const path = findPathToRoot(node.id, links);
        paths.push(path);
      }
    });
    
    let maxScore = 0;
    let criticalPath: string[] = [];
    
    paths.forEach(path => {
      const score = path.reduce((sum, nodeId) => {
        const node = nodes.find(n => n.id === nodeId);
        return sum + (node?.criticalityScore || 0);
      }, 0);
      
      if (score > maxScore) {
        maxScore = score;
        criticalPath = path;
      }
    });
    
    return criticalPath;
  }

  function calculateImpactAnalysis(nodeId: string, links: GraphLink[], nodes: GraphNode[]) {
    const affected = new Set<string>();
    const queue = [nodeId];
    
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (affected.has(current)) continue;
      affected.add(current);
      
      // Find all components that depend on this one
      links.forEach(link => {
        const targetId = typeof link.target === 'string' ? link.target : link.target.id;
        const sourceId = typeof link.source === 'string' ? link.source : link.source.id;
        
        if (targetId === current && !affected.has(sourceId)) {
          queue.push(sourceId);
        }
      });
    }
    
    return {
      affectedComponents: Array.from(affected),
      impactScore: affected.size / nodes.length,
      criticalComponents: Array.from(affected).filter(id => {
        const node = nodes.find(n => n.id === id);
        return node && node.criticalityScore > 0.7;
      })
    };
  }

  function forceCluster() {
    const strength = 0.2;
    let nodes: GraphNode[];
    let centers: { x: number; y: number }[];

    function force(alpha: number) {
      for (let i = 0; i < nodes.length; i++) {
        const node = nodes[i];
        const center = centers[node.cluster] || { x: 0, y: 0 };
        node.vx! += (center.x - node.x!) * strength * alpha;
        node.vy! += (center.y - node.y!) * strength * alpha;
      }
    }

    force.initialize = function(_nodes: GraphNode[]) {
      nodes = _nodes;
    };

    force.centers = function(_centers: { x: number; y: number }[]) {
      centers = _centers;
      return force;
    };

    return force;
  }

  function getClusterCenters(nodes: GraphNode[], width: number, height: number) {
    const clusterCount = Math.max(...nodes.map(n => n.cluster)) + 1;
    const centers = [];
    
    for (let i = 0; i < clusterCount; i++) {
      const angle = (i / clusterCount) * 2 * Math.PI;
      const radius = Math.min(width, height) * 0.3;
      centers.push({
        x: width / 2 + Math.cos(angle) * radius,
        y: height / 2 + Math.sin(angle) * radius
      });
    }
    
    return centers;
  }

  // Control functions
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
    setHighlightPath([]);
    setSelectedNodes(new Set());
  }

  function handleFitToScreen() {
    if (!containerRef.current) return;
    
    const svg = d3.select(svgRef.current);
    const bounds = svg.select('g').node()?.getBBox();
    if (!bounds) return;

    const width = containerRef.current.clientWidth;
    const height = containerRef.current.clientHeight;
    const scale = Math.min(width / bounds.width, height / bounds.height) * 0.85;
    
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
    link.download = `sbom-dependency-graph-${new Date().toISOString().split('T')[0]}.svg`;
    link.click();
    
    URL.revokeObjectURL(url);
  }

  function analyzeCircularDependencies() {
    const circular = graphData.circularDeps;
    if (circular.length > 0) {
      alert(`Found ${circular.length} circular dependencies:\n${circular.slice(0, 5).join('\n')}${circular.length > 5 ? '\n...' : ''}`);
    } else {
      alert('No circular dependencies detected!');
    }
  }

  function highlightCriticalPath() {
    setHighlightPath(graphData.criticalPath);
  }

  const stats = useMemo(() => {
    return {
      totalNodes: graphData.nodes.length,
      totalLinks: graphData.links.length,
      vulnerableNodes: graphData.nodes.filter(n => n.vulnerabilityLevel !== 'none').length,
      orphanNodes: graphData.nodes.filter(n => n.isOrphan).length,
      criticalNodes: graphData.nodes.filter(n => n.criticalityScore > 0.7).length,
      circularDeps: graphData.circularDeps.length,
      maxLevel: Math.max(...graphData.nodes.map(n => n.level)),
      avgDependencies: graphData.nodes.reduce((sum, n) => sum + n.dependencyCount, 0) / graphData.nodes.length,
    };
  }, [graphData]);

  if (!sbomData.components || !sbomData.dependencies) {
    return (
      <div className="bg-white rounded-xl shadow-sm p-8 text-center">
        <Network className="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No Dependency Data</h3>
        <p className="text-gray-600">This SBOM doesn't contain dependency information required for graph visualization.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Enhanced Controls Panel */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <div className="flex flex-wrap items-center gap-4 mb-6">
          <h2 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
            <Network className="w-6 h-6 text-blue-600" />
            Interactive Dependency Graph
          </h2>
          
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

          {/* Advanced Filters */}
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

          <select
            value={layoutType}
            onChange={(e) => setLayoutType(e.target.value as any)}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
          >
            <option value="hierarchical">Hierarchical</option>
            <option value="force">Force Layout</option>
            <option value="circular">Circular</option>
            <option value="clustered">Clustered</option>
          </select>

          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-600">Max Depth:</label>
            <input
              type="range"
              min="1"
              max="10"
              value={maxDepth}
              onChange={(e) => setMaxDepth(parseInt(e.target.value))}
              className="w-20"
            />
            <span className="text-sm text-gray-600 w-6">{maxDepth}</span>
          </div>
        </div>

        {/* Filter Toggles */}
        <div className="flex flex-wrap items-center gap-4 mb-4">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={showVulnerabilities}
              onChange={(e) => setShowVulnerabilities(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <Shield className="w-4 h-4" />
            Highlight Vulnerabilities
          </label>

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={showOrphans}
              onChange={(e) => setShowOrphans(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <Package className="w-4 h-4" />
            Show Isolated Components
          </label>

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={showTransitive}
              onChange={(e) => setShowTransitive(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <GitBranch className="w-4 h-4" />
            Show Transitive Dependencies
          </label>

          <div className="flex items-center gap-2 text-sm">
            <label className="text-gray-600">Min Criticality:</label>
            <input
              type="range"
              min="0"
              max="100"
              value={minCriticality * 100}
              onChange={(e) => setMinCriticality(parseInt(e.target.value) / 100)}
              className="w-20"
            />
            <span className="text-gray-600 w-8">{Math.round(minCriticality * 100)}%</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
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

          <div className="w-px h-6 bg-gray-300 mx-2"></div>

          <button
            onClick={highlightCriticalPath}
            className="flex items-center gap-1 px-3 py-2 text-sm text-red-600 hover:text-red-700 hover:bg-red-50 rounded-lg transition-colors"
            title="Highlight Critical Path"
          >
            <Zap className="w-4 h-4" />
            Critical Path
          </button>

          <button
            onClick={analyzeCircularDependencies}
            className="flex items-center gap-1 px-3 py-2 text-sm text-amber-600 hover:text-amber-700 hover:bg-amber-50 rounded-lg transition-colors"
            title="Analyze Circular Dependencies"
          >
            <RefreshCw className="w-4 h-4" />
            Circular Deps
          </button>

          <button
            onClick={() => setHighlightPath([])}
            className="flex items-center gap-1 px-3 py-2 text-sm text-gray-600 hover:text-gray-700 hover:bg-gray-50 rounded-lg transition-colors"
            title="Clear Highlights"
          >
            <EyeOff className="w-4 h-4" />
            Clear
          </button>
          
          <button
            onClick={exportGraph}
            className="flex items-center gap-1 px-3 py-2 text-sm text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded-lg transition-colors"
            title="Export Graph"
          >
            <Download className="w-4 h-4" />
            Export
          </button>

          {/* Stats Display */}
          <div className="ml-auto flex items-center gap-4 text-sm text-gray-600">
            <span className="flex items-center gap-1">
              <Package className="w-4 h-4" />
              {stats.totalNodes} nodes
            </span>
            <span className="flex items-center gap-1">
              <GitBranch className="w-4 h-4" />
              {stats.totalLinks} edges
            </span>
            {stats.vulnerableNodes > 0 && (
              <span className="flex items-center gap-1 text-red-600">
                <AlertTriangle className="w-4 h-4" />
                {stats.vulnerableNodes} at risk
              </span>
            )}
            {stats.circularDeps > 0 && (
              <span className="flex items-center gap-1 text-amber-600">
                <RefreshCw className="w-4 h-4" />
                {stats.circularDeps} circular
              </span>
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
            style={{ height: '700px' }}
          >
            <svg
              ref={svgRef}
              className="w-full h-full"
              style={{ background: 'linear-gradient(135deg, #F8FAFC 0%, #F1F5F9 100%)' }}
            />
            
            {/* Enhanced Legend */}
            <div className="absolute top-4 right-4 bg-white rounded-lg shadow-lg p-4 max-w-xs border border-gray-200">
              <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                <Compass className="w-4 h-4" />
                Legend
              </h4>
              
              <div className="space-y-3 text-sm">
                <div>
                  <p className="font-medium text-gray-700 mb-2">Component Types</p>
                  <div className="space-y-1">
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
                      <span>Other/Isolated</span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <p className="font-medium text-gray-700 mb-2">Risk Levels</p>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-red-200 border-2 border-red-600"></div>
                      <span>High Risk</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-yellow-200 border-2 border-yellow-600"></div>
                      <span>Medium Risk</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-green-200 border-2 border-green-600"></div>
                      <span>Low Risk</span>
                    </div>
                  </div>
                </div>

                <div>
                  <p className="font-medium text-gray-700 mb-2">Indicators</p>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-blue-500 relative">
                        <div className="absolute -top-1 -right-1 w-3 h-3 bg-blue-600 rounded-full text-white text-xs flex items-center justify-center">5</div>
                      </div>
                      <span>Dependency Count</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 bg-red-600" style={{ clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)' }}></div>
                      <span>Critical Component</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-1 bg-red-600"></div>
                      <span>Circular Dependency</span>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-4 pt-3 border-t border-gray-200 text-xs text-gray-500">
                <p>• Node size = impact level</p>
                <p>• Right-click for context menu</p>
                <p>• Double-click to trace path</p>
                <p>• Drag to reposition</p>
                <p>• Hover for details</p>
              </div>
            </div>

            {/* Analysis Status */}
            {isAnalyzing && (
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-white rounded-lg shadow-lg p-4 flex items-center gap-3">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                <span className="text-sm font-medium text-gray-900">Analyzing impact...</span>
              </div>
            )}
          </div>

          {/* Enhanced Side Panel */}
          {selectedComponent && (
            <div className="w-96 border-l border-gray-200 p-6 bg-gray-50 overflow-y-auto" style={{ height: '700px' }}>
              <div className="space-y-6">
                {/* Component Header */}
                <div className="bg-white rounded-lg p-4 border border-gray-200">
                  <div className="flex items-start gap-3 mb-3">
                    <div className={`p-2 rounded-lg ${
                      selectedComponent.type === 'framework' ? 'bg-amber-100 text-amber-700' :
                      selectedComponent.type === 'library' ? 'bg-emerald-100 text-emerald-700' :
                      selectedComponent.type === 'application' ? 'bg-purple-100 text-purple-700' :
                      'bg-gray-100 text-gray-700'
                    }`}>
                      {selectedComponent.type === 'framework' && <Layers className="w-5 h-5" />}
                      {selectedComponent.type === 'library' && <Package className="w-5 h-5" />}
                      {selectedComponent.type === 'application' && <Code className="w-5 h-5" />}
                      {!['framework', 'library', 'application'].includes(selectedComponent.type) && <FileText className="w-5 h-5" />}
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900 text-lg">{selectedComponent.name}</h3>
                      {selectedComponent.version && (
                        <p className="text-sm text-gray-600 mt-1">Version {selectedComponent.version}</p>
                      )}
                      <span className="inline-block mt-2 px-2 py-1 text-xs font-medium bg-gray-100 text-gray-700 rounded capitalize">
                        {selectedComponent.type}
                      </span>
                    </div>
                  </div>
                  
                  {selectedComponent.description && (
                    <p className="text-sm text-gray-600 mb-3">{selectedComponent.description}</p>
                  )}

                  {/* Component Metrics */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="text-center p-2 bg-blue-50 rounded">
                      <p className="text-lg font-bold text-blue-600">
                        {(() => {
                          const node = graphData.nodes.find(n => n.id === selectedComponent['bom-ref']);
                          return node?.dependencyCount || 0;
                        })()}
                      </p>
                      <p className="text-xs text-gray-600">Dependencies</p>
                    </div>
                    <div className="text-center p-2 bg-purple-50 rounded">
                      <p className="text-lg font-bold text-purple-600">
                        {(() => {
                          const node = graphData.nodes.find(n => n.id === selectedComponent['bom-ref']);
                          return node?.dependentCount || 0;
                        })()}
                      </p>
                      <p className="text-xs text-gray-600">Dependents</p>
                    </div>
                  </div>
                </div>

                {/* Dependencies List */}
                <div className="bg-white rounded-lg p-4 border border-gray-200">
                  <h4 className="font-medium text-gray-900 mb-3 flex items-center gap-2">
                    <GitBranch className="w-4 h-4" />
                    Direct Dependencies
                  </h4>
                  {(() => {
                    const deps = sbomData.dependencies?.find(d => d.ref === selectedComponent['bom-ref']);
                    if (!deps || deps.dependsOn.length === 0) {
                      return <p className="text-sm text-gray-500 italic">No direct dependencies</p>;
                    }
                    
                    return (
                      <div className="space-y-2 max-h-48 overflow-y-auto">
                        {deps.dependsOn.slice(0, 10).map((depRef, index) => {
                          const depComponent = sbomData.components?.find(c => c['bom-ref'] === depRef);
                          const depNode = graphData.nodes.find(n => n.id === depRef);
                          return depComponent ? (
                            <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded text-sm">
                              <div className="flex-1">
                                <p className="font-medium text-gray-900">{depComponent.name}</p>
                                <p className="text-gray-600">{depComponent.version || 'No version'}</p>
                              </div>
                              {depNode && (
                                <div className="flex items-center gap-1">
                                  {depNode.vulnerabilityLevel !== 'none' && (
                                    <AlertTriangle className="w-3 h-3 text-red-500" />
                                  )}
                                  <span className="text-xs text-gray-500">
                                    L{depNode.level}
                                  </span>
                                </div>
                              )}
                            </div>
                          ) : null;
                        })}
                        {deps.dependsOn.length > 10 && (
                          <p className="text-xs text-gray-500 text-center">
                            ... and {deps.dependsOn.length - 10} more
                          </p>
                        )}
                      </div>
                    );
                  })()}
                </div>

                {/* Security Information */}
                {selectedComponent.hashes && selectedComponent.hashes.length > 0 && (
                  <div className="bg-white rounded-lg p-4 border border-gray-200">
                    <h4 className="font-medium text-gray-900 mb-3 flex items-center gap-2">
                      <Lock className="w-4 h-4" />
                      Security Hashes
                    </h4>
                    <div className="space-y-2">
                      {selectedComponent.hashes.slice(0, 3).map((hash, index) => (
                        <div key={index} className="p-2 bg-gray-50 rounded">
                          <p className="text-xs font-medium text-gray-700 mb-1">{hash.alg}</p>
                          <p className="text-xs font-mono text-gray-600 break-all">
                            {hash.content.substring(0, 40)}...
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* License Information */}
                {selectedComponent.licenses && selectedComponent.licenses.length > 0 && (
                  <div className="bg-white rounded-lg p-4 border border-gray-200">
                    <h4 className="font-medium text-gray-900 mb-3 flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Licenses
                    </h4>
                    <div className="space-y-2">
                      {selectedComponent.licenses.map((license, index) => (
                        <div key={index} className="flex items-center gap-2 p-2 bg-emerald-50 rounded">
                          <Shield className="w-3 h-3 text-emerald-600" />
                          <span className="text-sm text-emerald-800">
                            {license.license?.name || license.license?.id || 'Unknown License'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Component Analysis */}
                <div className="bg-white rounded-lg p-4 border border-gray-200">
                  <h4 className="font-medium text-gray-900 mb-3 flex items-center gap-2">
                    <BarChart3 className="w-4 h-4" />
                    Analysis
                  </h4>
                  {(() => {
                    const node = graphData.nodes.find(n => n.id === selectedComponent['bom-ref']);
                    if (!node) return null;
                    
                    return (
                      <div className="space-y-3">
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-gray-600">Criticality Score</span>
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div 
                                className={`h-full transition-all duration-300 ${
                                  node.criticalityScore > 0.7 ? 'bg-red-500' :
                                  node.criticalityScore > 0.4 ? 'bg-yellow-500' : 'bg-green-500'
                                }`}
                                style={{ width: `${node.criticalityScore * 100}%` }}
                              ></div>
                            </div>
                            <span className="text-sm font-medium">
                              {Math.round(node.criticalityScore * 100)}%
                            </span>
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div className="text-center p-2 bg-gray-50 rounded">
                            <p className="font-medium text-gray-900">{node.level}</p>
                            <p className="text-gray-600">Depth Level</p>
                          </div>
                          <div className="text-center p-2 bg-gray-50 rounded">
                            <p className="font-medium text-gray-900">{node.cluster}</p>
                            <p className="text-gray-600">Cluster ID</p>
                          </div>
                        </div>

                        {node.isOrphan && (
                          <div className="p-2 bg-amber-50 border border-amber-200 rounded">
                            <p className="text-xs text-amber-800 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" />
                              Isolated component with no dependencies
                            </p>
                          </div>
                        )}

                        {node.vulnerabilityLevel !== 'none' && (
                          <div className="p-2 bg-red-50 border border-red-200 rounded">
                            <p className="text-xs text-red-800 flex items-center gap-1">
                              <Shield className="w-3 h-3" />
                              {node.vulnerabilityLevel.toUpperCase()} security risk detected
                            </p>
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Enhanced Statistics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <div className="bg-white rounded-xl shadow-sm p-4 text-center">
          <Package className="w-6 h-6 text-blue-600 mx-auto mb-2" />
          <p className="text-xl font-bold text-gray-900">{stats.totalNodes}</p>
          <p className="text-sm text-gray-600">Components</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm p-4 text-center">
          <GitBranch className="w-6 h-6 text-purple-600 mx-auto mb-2" />
          <p className="text-xl font-bold text-gray-900">{stats.totalLinks}</p>
          <p className="text-sm text-gray-600">Dependencies</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm p-4 text-center">
          <AlertTriangle className="w-6 h-6 text-red-600 mx-auto mb-2" />
          <p className="text-xl font-bold text-gray-900">{stats.vulnerableNodes}</p>
          <p className="text-sm text-gray-600">At Risk</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm p-4 text-center">
          <Target className="w-6 h-6 text-amber-600 mx-auto mb-2" />
          <p className="text-xl font-bold text-gray-900">{stats.criticalNodes}</p>
          <p className="text-sm text-gray-600">Critical</p>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-4 text-center">
          <RefreshCw className="w-6 h-6 text-orange-600 mx-auto mb-2" />
          <p className="text-xl font-bold text-gray-900">{stats.circularDeps}</p>
          <p className="text-sm text-gray-600">Circular</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm p-4 text-center">
          <Layers className="w-6 h-6 text-indigo-600 mx-auto mb-2" />
          <p className="text-xl font-bold text-gray-900">{stats.maxLevel}</p>
          <p className="text-sm text-gray-600">Max Depth</p>
        </div>
      </div>

      {/* Analysis Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Critical Path Analysis */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Zap className="w-5 h-5 text-red-600" />
            Critical Path Analysis
          </h3>
          
          {graphData.criticalPath.length > 0 ? (
            <div className="space-y-3">
              <p className="text-sm text-gray-600 mb-3">
                Components in the most critical dependency chain:
              </p>
              {graphData.criticalPath.slice(0, 5).map((nodeId, index) => {
                const node = graphData.nodes.find(n => n.id === nodeId);
                const component = node?.component;
                return component ? (
                  <div key={index} className="flex items-center gap-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <div className="w-6 h-6 bg-red-100 rounded-full flex items-center justify-center text-xs font-bold text-red-600">
                      {index + 1}
                    </div>
                    <div className="flex-1">
                      <p className="font-medium text-gray-900">{component.name}</p>
                      <p className="text-sm text-gray-600">{component.version}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium text-red-600">
                        {Math.round((node?.criticalityScore || 0) * 100)}%
                      </p>
                    </div>
                  </div>
                ) : null;
              })}
              {graphData.criticalPath.length > 5 && (
                <p className="text-xs text-gray-500 text-center">
                  ... and {graphData.criticalPath.length - 5} more components
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-gray-500 italic">No critical path identified</p>
          )}
        </div>

        {/* Circular Dependencies */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <RefreshCw className="w-5 h-5 text-amber-600" />
            Circular Dependencies
          </h3>
          
          {graphData.circularDeps.length > 0 ? (
            <div className="space-y-2">
              <p className="text-sm text-gray-600 mb-3">
                Detected {graphData.circularDeps.length} circular dependency relationships:
              </p>
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {graphData.circularDeps.slice(0, 8).map((dep, index) => (
                  <div key={index} className="p-2 bg-amber-50 border border-amber-200 rounded text-sm">
                    <p className="font-mono text-amber-800">{dep}</p>
                  </div>
                ))}
              </div>
              {graphData.circularDeps.length > 8 && (
                <p className="text-xs text-gray-500 text-center">
                  ... and {graphData.circularDeps.length - 8} more
                </p>
              )}
            </div>
          ) : (
            <div className="text-center py-4">
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-2">
                <Shield className="w-6 h-6 text-green-600" />
              </div>
              <p className="text-sm text-green-800 font-medium">No circular dependencies detected</p>
              <p className="text-xs text-gray-600">Your dependency graph is clean!</p>
            </div>
          )}
        </div>
      </div>

      {/* Usage Instructions */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-xl p-6">
        <div className="flex items-start gap-3">
          <Settings className="w-5 h-5 text-blue-600 mt-0.5" />
          <div>
            <h3 className="text-lg font-semibold text-blue-900 mb-3">Advanced Graph Features</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-800">
              <div>
                <h4 className="font-medium mb-2">Navigation</h4>
                <ul className="space-y-1">
                  <li>• Pan by dragging empty space</li>
                  <li>• Zoom with mouse wheel or controls</li>
                  <li>• Double-click to trace dependency path</li>
                  <li>• Right-click for context menu</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium mb-2">Analysis</h4>
                <ul className="space-y-1">
                  <li>• Red triangles mark critical components</li>
                  <li>• Dashed circles show vulnerability risks</li>
                  <li>• Blue badges display dependency counts</li>
                  <li>• Gray nodes are isolated components</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}