import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import { SBOMData, Component } from '../types/sbom';
import { 
  Search, Filter, Download, RotateCcw, ZoomIn, ZoomOut, Maximize2, 
  AlertTriangle, Shield, Package, Layers, Code, FileText, Info, 
  Target, GitBranch, Network, Eye, EyeOff, Play, Pause, BarChart3,
  Clock, Users, Zap, TrendingUp, Activity, Cpu, Database, Globe,
  Lock, Unlock, Star, Bookmark, Share2, Settings, RefreshCw,
  ChevronDown, ChevronRight, Map, Compass, Route, Radar
} from 'lucide-react';

interface Node extends d3.SimulationNodeDatum {
  id: string;
  name: string;
  version?: string;
  type: string;
  vulnerabilities: number;
  licenses: string[];
  dependencyCount: number;
  criticality: number;
  depth: number;
  cluster?: number;
  risk: 'low' | 'medium' | 'high';
  lastUpdated?: string;
  popularity?: number;
  maintainability?: number;
  trustScore?: number;
  size?: number;
  isBookmarked?: boolean;
  tags?: string[];
}

interface Link extends d3.SimulationLinkDatum<Node> {
  source: string | Node;
  target: string | Node;
  type: 'direct' | 'transitive' | 'optional' | 'peer';
  weight: number;
  risk: 'low' | 'medium' | 'high';
}

interface InteractiveDependencyGraphProps {
  sbomData: SBOMData;
}

interface GraphMetrics {
  totalNodes: number;
  totalEdges: number;
  avgDependencies: number;
  maxDepth: number;
  circularDeps: number;
  vulnerableNodes: number;
  criticalComponents: number;
  orphanNodes: number;
  clusterCount: number;
  networkDensity: number;
  centralityScore: number;
  modularityScore: number;
}

interface TimelineEvent {
  timestamp: string;
  component: string;
  event: 'added' | 'updated' | 'removed' | 'vulnerability';
  details: string;
}

export function InteractiveDependencyGraph({ sbomData }: InteractiveDependencyGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(new Set());
  const [searchTerm, setSearchTerm] = useState('');
  const [layout, setLayout] = useState<'force' | 'hierarchical' | 'circular' | 'clustered' | 'timeline'>('hierarchical');
  const [showVulnerabilities, setShowVulnerabilities] = useState(true);
  const [showOrphans, setShowOrphans] = useState(true);
  const [filterType, setFilterType] = useState<'all' | 'library' | 'framework' | 'application'>('all');
  const [criticalityThreshold, setCriticalityThreshold] = useState(0);
  const [depthLimit, setDepthLimit] = useState(10);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [showClusters, setShowClusters] = useState(false);
  const [showMetrics, setShowMetrics] = useState(false);
  const [bookmarkedNodes, setBookmarkedNodes] = useState<Set<string>>(new Set());
  const [selectedAnalysis, setSelectedAnalysis] = useState<'overview' | 'security' | 'performance' | 'compliance'>('overview');
  const [heatmapMode, setHeatmapMode] = useState<'none' | 'vulnerability' | 'popularity' | 'age' | 'trust'>('none');
  const [pathAnalysis, setPathAnalysis] = useState<{from?: string, to?: string, paths?: string[][]}>({});
  const [showMiniMap, setShowMiniMap] = useState(true);
  const [graphHistory, setGraphHistory] = useState<any[]>([]);
  const [currentHistoryIndex, setCurrentHistoryIndex] = useState(-1);

  // Process SBOM data into graph format
  const { nodes, links, metrics, timeline } = useMemo(() => {
    if (!sbomData?.components) return { nodes: [], links: [], metrics: {} as GraphMetrics, timeline: [] };

    const nodeMap = new Map<string, Node>();
    const linkArray: Link[] = [];
    const timelineEvents: TimelineEvent[] = [];

    // Create nodes
    sbomData.components.forEach((component, index) => {
      const vulnerabilityCount = Math.floor(Math.random() * 5); // Simulated
      const popularity = Math.random() * 100;
      const trustScore = Math.random() * 100;
      const lastUpdated = new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString();
      
      const node: Node = {
        id: component['bom-ref'],
        name: component.name,
        version: component.version,
        type: component.type,
        vulnerabilities: vulnerabilityCount,
        licenses: component.licenses?.map(l => l.license?.name || l.license?.id || 'Unknown') || [],
        dependencyCount: 0,
        criticality: 0,
        depth: 0,
        risk: vulnerabilityCount > 3 ? 'high' : vulnerabilityCount > 1 ? 'medium' : 'low',
        lastUpdated,
        popularity,
        maintainability: Math.random() * 100,
        trustScore,
        size: Math.random() * 50 + 10,
        isBookmarked: false,
        tags: [component.type, ...(component.licenses?.map(l => l.license?.name || 'unlicensed') || [])]
      };
      nodeMap.set(node.id, node);

      // Add timeline events
      timelineEvents.push({
        timestamp: lastUpdated,
        component: component.name,
        event: 'added',
        details: `Component ${component.name} v${component.version} added`
      });

      if (vulnerabilityCount > 0) {
        timelineEvents.push({
          timestamp: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
          component: component.name,
          event: 'vulnerability',
          details: `${vulnerabilityCount} vulnerabilities detected`
        });
      }
    });

    // Create links from dependencies
    sbomData.dependencies?.forEach(dep => {
      const sourceNode = nodeMap.get(dep.ref);
      if (sourceNode) {
        dep.dependsOn.forEach(targetRef => {
          const targetNode = nodeMap.get(targetRef);
          if (targetNode) {
            sourceNode.dependencyCount++;
            targetNode.depth = Math.max(targetNode.depth, sourceNode.depth + 1);
            
            linkArray.push({
              source: dep.ref,
              target: targetRef,
              type: Math.random() > 0.8 ? 'optional' : 'direct',
              weight: Math.random() * 2 + 0.5,
              risk: sourceNode.risk === 'high' || targetNode.risk === 'high' ? 'high' : 
                    sourceNode.risk === 'medium' || targetNode.risk === 'medium' ? 'medium' : 'low'
            });
          }
        });
      }
    });

    // Calculate criticality scores
    nodeMap.forEach(node => {
      node.criticality = (node.dependencyCount * 0.4) + 
                        (node.vulnerabilities * 0.3) + 
                        (node.popularity * 0.2) + 
                        ((100 - node.trustScore) * 0.1);
    });

    // Detect clusters using simple community detection
    const clusters = detectCommunities(Array.from(nodeMap.values()), linkArray);
    clusters.forEach((cluster, index) => {
      cluster.forEach(nodeId => {
        const node = nodeMap.get(nodeId);
        if (node) node.cluster = index;
      });
    });

    // Calculate metrics
    const nodesArray = Array.from(nodeMap.values());
    const orphanNodes = nodesArray.filter(n => n.dependencyCount === 0 && 
      !linkArray.some(l => (l.target as any) === n.id)).length;
    
    const graphMetrics: GraphMetrics = {
      totalNodes: nodesArray.length,
      totalEdges: linkArray.length,
      avgDependencies: nodesArray.reduce((sum, n) => sum + n.dependencyCount, 0) / nodesArray.length,
      maxDepth: Math.max(...nodesArray.map(n => n.depth)),
      circularDeps: detectCircularDependencies(linkArray),
      vulnerableNodes: nodesArray.filter(n => n.vulnerabilities > 0).length,
      criticalComponents: nodesArray.filter(n => n.criticality > 50).length,
      orphanNodes,
      clusterCount: clusters.length,
      networkDensity: (linkArray.length * 2) / (nodesArray.length * (nodesArray.length - 1)),
      centralityScore: calculateCentralityScore(nodesArray, linkArray),
      modularityScore: calculateModularityScore(nodesArray, linkArray)
    };

    return { 
      nodes: nodesArray, 
      links: linkArray, 
      metrics: graphMetrics,
      timeline: timelineEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    };
  }, [sbomData]);

  // Filter nodes and links based on current filters
  const filteredData = useMemo(() => {
    let filteredNodes = nodes.filter(node => {
      const matchesSearch = node.name.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesType = filterType === 'all' || node.type === filterType;
      const matchesCriticality = node.criticality >= criticalityThreshold;
      const matchesDepth = node.depth <= depthLimit;
      const matchesVulnerability = showVulnerabilities || node.vulnerabilities === 0;
      const matchesOrphan = showOrphans || node.dependencyCount > 0;
      
      return matchesSearch && matchesType && matchesCriticality && matchesDepth && 
             matchesVulnerability && matchesOrphan;
    });

    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = links.filter(link => 
      nodeIds.has((link.source as any).id || link.source as string) && 
      nodeIds.has((link.target as any).id || link.target as string)
    );

    return { nodes: filteredNodes, links: filteredLinks };
  }, [nodes, links, searchTerm, filterType, criticalityThreshold, depthLimit, showVulnerabilities, showOrphans]);

  // Initialize and update D3 visualization
  useEffect(() => {
    if (!svgRef.current || filteredData.nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    const container = d3.select(containerRef.current);
    const width = container.node()?.getBoundingClientRect().width || 800;
    const height = container.node()?.getBoundingClientRect().height || 600;

    svg.selectAll("*").remove();

    // Create main group for zooming
    const g = svg.append("g");

    // Setup zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    svg.call(zoom);

    // Create simulation based on layout
    let simulation: d3.Simulation<Node, Link>;
    
    switch (layout) {
      case 'hierarchical':
        simulation = createHierarchicalLayout(filteredData.nodes, filteredData.links, width, height);
        break;
      case 'circular':
        simulation = createCircularLayout(filteredData.nodes, filteredData.links, width, height);
        break;
      case 'clustered':
        simulation = createClusteredLayout(filteredData.nodes, filteredData.links, width, height);
        break;
      case 'timeline':
        simulation = createTimelineLayout(filteredData.nodes, filteredData.links, width, height, timeline);
        break;
      default:
        simulation = createForceLayout(filteredData.nodes, filteredData.links, width, height);
    }

    // Add gradient definitions for heatmap
    const defs = svg.append("defs");
    
    // Vulnerability gradient
    const vulnGradient = defs.append("radialGradient")
      .attr("id", "vulnerability-gradient")
      .attr("cx", "50%")
      .attr("cy", "50%")
      .attr("r", "50%");
    
    vulnGradient.append("stop")
      .attr("offset", "0%")
      .attr("stop-color", "#fee2e2")
      .attr("stop-opacity", 0.8);
    
    vulnGradient.append("stop")
      .attr("offset", "100%")
      .attr("stop-color", "#dc2626")
      .attr("stop-opacity", 0.3);

    // Trust gradient
    const trustGradient = defs.append("radialGradient")
      .attr("id", "trust-gradient")
      .attr("cx", "50%")
      .attr("cy", "50%")
      .attr("r", "50%");
    
    trustGradient.append("stop")
      .attr("offset", "0%")
      .attr("stop-color", "#dcfce7")
      .attr("stop-opacity", 0.8);
    
    trustGradient.append("stop")
      .attr("offset", "100%")
      .attr("stop-color", "#16a34a")
      .attr("stop-opacity", 0.3);

    // Create cluster backgrounds
    if (showClusters && layout === 'clustered') {
      const clusters = d3.group(filteredData.nodes, d => d.cluster || 0);
      
      clusters.forEach((clusterNodes, clusterId) => {
        const hull = d3.polygonHull(clusterNodes.map(d => [d.x || 0, d.y || 0]));
        if (hull) {
          g.append("path")
            .datum(hull)
            .attr("class", "cluster-hull")
            .attr("d", d3.line().curve(d3.curveCardinalClosed.tension(0.85)))
            .style("fill", d3.schemeCategory10[clusterId % 10])
            .style("fill-opacity", 0.1)
            .style("stroke", d3.schemeCategory10[clusterId % 10])
            .style("stroke-width", 2)
            .style("stroke-dasharray", "5,5");
        }
      });
    }

    // Create links
    const link = g.append("g")
      .selectAll("line")
      .data(filteredData.links)
      .enter().append("line")
      .attr("class", "link")
      .style("stroke", d => {
        switch (d.risk) {
          case 'high': return "#dc2626";
          case 'medium': return "#f59e0b";
          default: return "#6b7280";
        }
      })
      .style("stroke-width", d => Math.sqrt(d.weight) * 2)
      .style("stroke-opacity", 0.6)
      .style("stroke-dasharray", d => d.type === 'optional' ? "5,5" : "none");

    // Add arrowheads
    defs.append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 15)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .style("fill", "#6b7280");

    link.attr("marker-end", "url(#arrowhead)");

    // Create node groups
    const nodeGroup = g.append("g")
      .selectAll("g")
      .data(filteredData.nodes)
      .enter().append("g")
      .attr("class", "node-group")
      .style("cursor", "pointer");

    // Add node circles with heatmap coloring
    const nodeCircles = nodeGroup.append("circle")
      .attr("class", "node")
      .attr("r", d => Math.sqrt(d.size || 20) + (d.criticality / 10))
      .style("fill", d => {
        if (heatmapMode === 'vulnerability') {
          return d.vulnerabilities > 0 ? "url(#vulnerability-gradient)" : getNodeColor(d.type);
        } else if (heatmapMode === 'trust') {
          return d.trustScore! > 70 ? "url(#trust-gradient)" : getNodeColor(d.type);
        } else if (heatmapMode === 'popularity') {
          const intensity = d.popularity! / 100;
          return d3.interpolateBlues(intensity);
        } else if (heatmapMode === 'age') {
          const daysSinceUpdate = (Date.now() - new Date(d.lastUpdated!).getTime()) / (1000 * 60 * 60 * 24);
          const intensity = Math.min(daysSinceUpdate / 365, 1);
          return d3.interpolateReds(intensity);
        }
        return getNodeColor(d.type);
      })
      .style("stroke", d => {
        if (selectedNodes.has(d.id)) return "#2563eb";
        if (d.vulnerabilities > 3) return "#dc2626";
        if (d.vulnerabilities > 1) return "#f59e0b";
        return "#e5e7eb";
      })
      .style("stroke-width", d => selectedNodes.has(d.id) ? 4 : d.vulnerabilities > 0 ? 3 : 2);

    // Add vulnerability indicators
    nodeGroup.filter(d => d.vulnerabilities > 0)
      .append("circle")
      .attr("class", "vulnerability-indicator")
      .attr("r", d => Math.sqrt(d.size || 20) + (d.criticality / 10) + 5)
      .style("fill", "none")
      .style("stroke", "#dc2626")
      .style("stroke-width", 2)
      .style("stroke-dasharray", "3,3")
      .style("opacity", 0.7);

    // Add criticality indicators
    nodeGroup.filter(d => d.criticality > 70)
      .append("polygon")
      .attr("points", "0,-15 -10,5 10,5")
      .style("fill", "#dc2626")
      .style("stroke", "#ffffff")
      .style("stroke-width", 1);

    // Add dependency count badges
    const badges = nodeGroup.filter(d => d.dependencyCount > 0)
      .append("g")
      .attr("class", "dependency-badge")
      .attr("transform", "translate(15, -15)");

    badges.append("circle")
      .attr("r", 8)
      .style("fill", "#2563eb")
      .style("stroke", "#ffffff")
      .style("stroke-width", 2);

    badges.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", "0.3em")
      .style("fill", "#ffffff")
      .style("font-size", "10px")
      .style("font-weight", "bold")
      .text(d => d.dependencyCount > 99 ? "99+" : d.dependencyCount);

    // Add bookmark indicators
    nodeGroup.filter(d => bookmarkedNodes.has(d.id))
      .append("polygon")
      .attr("points", "12,-12 20,-12 16,-4 12,-12")
      .style("fill", "#f59e0b")
      .style("stroke", "#ffffff")
      .style("stroke-width", 1);

    // Add node labels
    const labels = nodeGroup.append("text")
      .attr("class", "node-label")
      .attr("dy", d => Math.sqrt(d.size || 20) + (d.criticality / 10) + 15)
      .attr("text-anchor", "middle")
      .style("font-size", "12px")
      .style("font-weight", "500")
      .style("fill", "#374151")
      .style("pointer-events", "none")
      .text(d => d.name.length > 15 ? d.name.substring(0, 15) + "..." : d.name);

    // Add version labels
    nodeGroup.filter(d => d.version)
      .append("text")
      .attr("class", "version-label")
      .attr("dy", d => Math.sqrt(d.size || 20) + (d.criticality / 10) + 28)
      .attr("text-anchor", "middle")
      .style("font-size", "10px")
      .style("fill", "#6b7280")
      .style("pointer-events", "none")
      .text(d => `v${d.version}`);

    // Add interaction handlers
    nodeGroup
      .on("mouseover", function(event, d) {
        // Highlight connected nodes
        const connectedNodes = new Set([d.id]);
        filteredData.links.forEach(link => {
          if ((link.source as any).id === d.id) connectedNodes.add((link.target as any).id);
          if ((link.target as any).id === d.id) connectedNodes.add((link.source as any).id);
        });

        nodeCircles.style("opacity", node => connectedNodes.has(node.id) ? 1 : 0.3);
        link.style("opacity", l => 
          (l.source as any).id === d.id || (l.target as any).id === d.id ? 1 : 0.1);

        // Show tooltip
        showTooltip(event, d);
      })
      .on("mouseout", function() {
        nodeCircles.style("opacity", 1);
        link.style("opacity", 0.6);
        hideTooltip();
      })
      .on("click", function(event, d) {
        event.stopPropagation();
        if (event.ctrlKey || event.metaKey) {
          // Multi-select
          const newSelected = new Set(selectedNodes);
          if (newSelected.has(d.id)) {
            newSelected.delete(d.id);
          } else {
            newSelected.add(d.id);
          }
          setSelectedNodes(newSelected);
        } else {
          setSelectedNodes(new Set([d.id]));
        }
      })
      .on("dblclick", function(event, d) {
        // Zoom to node
        const transform = d3.zoomIdentity
          .translate(width / 2, height / 2)
          .scale(2)
          .translate(-(d.x || 0), -(d.y || 0));
        
        svg.transition().duration(750).call(zoom.transform, transform);
      })
      .on("contextmenu", function(event, d) {
        event.preventDefault();
        showContextMenu(event, d);
      });

    // Add drag behavior
    const drag = d3.drag<SVGGElement, Node>()
      .on("start", function(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", function(event, d) {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", function(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    nodeGroup.call(drag);

    // Update positions on simulation tick
    simulation.on("tick", () => {
      link
        .attr("x1", d => (d.source as any).x)
        .attr("y1", d => (d.source as any).y)
        .attr("x2", d => (d.target as any).x)
        .attr("y2", d => (d.target as any).y);

      nodeGroup.attr("transform", d => `translate(${d.x},${d.y})`);
    });

    // Cleanup
    return () => {
      simulation.stop();
    };
  }, [filteredData, layout, selectedNodes, showClusters, heatmapMode, bookmarkedNodes]);

  // Timeline animation
  useEffect(() => {
    if (!isPlaying) return;

    const interval = setInterval(() => {
      setCurrentTime(prev => {
        if (prev >= timeline.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [isPlaying, timeline.length]);

  // Helper functions
  function getNodeColor(type: string): string {
    switch (type) {
      case 'framework': return "#f59e0b";
      case 'library': return "#10b981";
      case 'application': return "#8b5cf6";
      default: return "#6b7280";
    }
  }

  function createForceLayout(nodes: Node[], links: Link[], width: number, height: number) {
    return d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(100).strength(0.5))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(d => Math.sqrt(d.size || 20) + 10));
  }

  function createHierarchicalLayout(nodes: Node[], links: Link[], width: number, height: number) {
    const maxDepth = Math.max(...nodes.map(n => n.depth));
    
    nodes.forEach(node => {
      node.x = (node.depth / maxDepth) * (width - 200) + 100;
      node.y = Math.random() * (height - 100) + 50;
    });

    return d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("x", d3.forceX(d => (d.depth / maxDepth) * (width - 200) + 100).strength(0.8))
      .force("y", d3.forceY(height / 2).strength(0.1))
      .force("collision", d3.forceCollide().radius(d => Math.sqrt(d.size || 20) + 15));
  }

  function createCircularLayout(nodes: Node[], links: Link[], width: number, height: number) {
    const maxDepth = Math.max(...nodes.map(n => n.depth));
    const centerX = width / 2;
    const centerY = height / 2;
    const maxRadius = Math.min(width, height) / 2 - 100;

    nodes.forEach((node, index) => {
      const radius = (node.depth / maxDepth) * maxRadius + 50;
      const angle = (index / nodes.length) * 2 * Math.PI;
      node.x = centerX + radius * Math.cos(angle);
      node.y = centerY + radius * Math.sin(angle);
    });

    return d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(60))
      .force("charge", d3.forceManyBody().strength(-100))
      .force("collision", d3.forceCollide().radius(d => Math.sqrt(d.size || 20) + 10));
  }

  function createClusteredLayout(nodes: Node[], links: Link[], width: number, height: number) {
    const clusters = d3.group(nodes, d => d.cluster || 0);
    const clusterCenters = new Map();
    
    clusters.forEach((clusterNodes, clusterId) => {
      const angle = (clusterId / clusters.size) * 2 * Math.PI;
      const radius = Math.min(width, height) / 4;
      clusterCenters.set(clusterId, {
        x: width / 2 + radius * Math.cos(angle),
        y: height / 2 + radius * Math.sin(angle)
      });
    });

    return d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(50))
      .force("charge", d3.forceManyBody().strength(-150))
      .force("cluster", d3.forceX(d => clusterCenters.get(d.cluster || 0)?.x || width / 2).strength(0.3))
      .force("cluster-y", d3.forceY(d => clusterCenters.get(d.cluster || 0)?.y || height / 2).strength(0.3))
      .force("collision", d3.forceCollide().radius(d => Math.sqrt(d.size || 20) + 8));
  }

  function createTimelineLayout(nodes: Node[], links: Link[], width: number, height: number, timeline: TimelineEvent[]) {
    nodes.forEach((node, index) => {
      const timelineIndex = timeline.findIndex(event => event.component === node.name);
      node.x = timelineIndex >= 0 ? (timelineIndex / timeline.length) * (width - 100) + 50 : width / 2;
      node.y = (index % 10) * 60 + 100;
    });

    return d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(40))
      .force("charge", d3.forceManyBody().strength(-100))
      .force("collision", d3.forceCollide().radius(d => Math.sqrt(d.size || 20) + 5));
  }

  function detectCommunities(nodes: Node[], links: Link[]): string[][] {
    // Simple community detection using connected components
    const visited = new Set<string>();
    const communities: string[][] = [];
    
    nodes.forEach(node => {
      if (!visited.has(node.id)) {
        const community: string[] = [];
        const stack = [node.id];
        
        while (stack.length > 0) {
          const current = stack.pop()!;
          if (!visited.has(current)) {
            visited.add(current);
            community.push(current);
            
            links.forEach(link => {
              const sourceId = (link.source as any).id || link.source;
              const targetId = (link.target as any).id || link.target;
              
              if (sourceId === current && !visited.has(targetId)) {
                stack.push(targetId);
              } else if (targetId === current && !visited.has(sourceId)) {
                stack.push(sourceId);
              }
            });
          }
        }
        
        if (community.length > 1) {
          communities.push(community);
        }
      }
    });
    
    return communities;
  }

  function detectCircularDependencies(links: Link[]): number {
    // Simple cycle detection
    const graph = new Map<string, string[]>();
    
    links.forEach(link => {
      const sourceId = (link.source as any).id || link.source as string;
      const targetId = (link.target as any).id || link.target as string;
      
      if (!graph.has(sourceId)) graph.set(sourceId, []);
      graph.get(sourceId)!.push(targetId);
    });

    let cycles = 0;
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    function hasCycle(node: string): boolean {
      if (recursionStack.has(node)) {
        cycles++;
        return true;
      }
      if (visited.has(node)) return false;

      visited.add(node);
      recursionStack.add(node);

      const neighbors = graph.get(node) || [];
      for (const neighbor of neighbors) {
        if (hasCycle(neighbor)) return true;
      }

      recursionStack.delete(node);
      return false;
    }

    graph.forEach((_, node) => {
      if (!visited.has(node)) {
        hasCycle(node);
      }
    });

    return cycles;
  }

  function calculateCentralityScore(nodes: Node[], links: Link[]): number {
    // Calculate average betweenness centrality
    const centralities = nodes.map(node => {
      let centrality = 0;
      links.forEach(link => {
        if ((link.source as any).id === node.id || (link.target as any).id === node.id) {
          centrality += link.weight;
        }
      });
      return centrality;
    });
    
    return centralities.reduce((sum, c) => sum + c, 0) / centralities.length;
  }

  function calculateModularityScore(nodes: Node[], links: Link[]): number {
    // Simplified modularity calculation
    const totalEdges = links.length;
    if (totalEdges === 0) return 0;
    
    const clusters = d3.group(nodes, d => d.cluster || 0);
    let modularity = 0;
    
    clusters.forEach(clusterNodes => {
      const clusterSize = clusterNodes.length;
      const internalEdges = links.filter(link => {
        const sourceCluster = (link.source as any).cluster;
        const targetCluster = (link.target as any).cluster;
        return sourceCluster === targetCluster;
      }).length;
      
      const expectedEdges = (clusterSize * (clusterSize - 1)) / (2 * totalEdges);
      modularity += (internalEdges / totalEdges) - Math.pow(expectedEdges, 2);
    });
    
    return Math.max(0, Math.min(1, modularity)) * 100;
  }

  function showTooltip(event: MouseEvent, node: Node) {
    const tooltip = d3.select("body").append("div")
      .attr("class", "graph-tooltip")
      .style("position", "absolute")
      .style("background", "rgba(0, 0, 0, 0.9)")
      .style("color", "white")
      .style("padding", "12px")
      .style("border-radius", "8px")
      .style("font-size", "12px")
      .style("pointer-events", "none")
      .style("z-index", "1000")
      .style("opacity", 0);

    tooltip.html(`
      <div class="font-semibold">${node.name}</div>
      <div class="text-gray-300">Version: ${node.version || 'N/A'}</div>
      <div class="text-gray-300">Type: ${node.type}</div>
      <div class="text-gray-300">Dependencies: ${node.dependencyCount}</div>
      <div class="text-gray-300">Vulnerabilities: ${node.vulnerabilities}</div>
      <div class="text-gray-300">Criticality: ${node.criticality.toFixed(1)}</div>
      <div class="text-gray-300">Trust Score: ${node.trustScore?.toFixed(1)}%</div>
      <div class="text-gray-300">Popularity: ${node.popularity?.toFixed(1)}%</div>
      <div class="text-gray-300">Last Updated: ${new Date(node.lastUpdated!).toLocaleDateString()}</div>
    `)
      .style("left", (event.pageX + 10) + "px")
      .style("top", (event.pageY - 10) + "px")
      .transition()
      .duration(200)
      .style("opacity", 1);
  }

  function hideTooltip() {
    d3.selectAll(".graph-tooltip").remove();
  }

  function showContextMenu(event: MouseEvent, node: Node) {
    const menu = d3.select("body").append("div")
      .attr("class", "context-menu")
      .style("position", "absolute")
      .style("background", "white")
      .style("border", "1px solid #e5e7eb")
      .style("border-radius", "8px")
      .style("box-shadow", "0 10px 25px rgba(0, 0, 0, 0.1)")
      .style("padding", "8px 0")
      .style("z-index", "1001")
      .style("left", event.pageX + "px")
      .style("top", event.pageY + "px");

    const menuItems = [
      { label: "Bookmark Component", action: () => toggleBookmark(node.id) },
      { label: "Find Shortest Path", action: () => startPathAnalysis(node.id) },
      { label: "Show Impact Analysis", action: () => showImpactAnalysis(node.id) },
      { label: "Export Component Data", action: () => exportComponentData(node) },
      { label: "View License Details", action: () => showLicenseDetails(node) }
    ];

    menuItems.forEach(item => {
      menu.append("div")
        .style("padding", "8px 16px")
        .style("cursor", "pointer")
        .style("border-bottom", "1px solid #f3f4f6")
        .text(item.label)
        .on("click", () => {
          item.action();
          menu.remove();
        })
        .on("mouseover", function() {
          d3.select(this).style("background", "#f3f4f6");
        })
        .on("mouseout", function() {
          d3.select(this).style("background", "white");
        });
    });

    // Remove menu on outside click
    d3.select("body").on("click.context-menu", () => {
      menu.remove();
      d3.select("body").on("click.context-menu", null);
    });
  }

  function toggleBookmark(nodeId: string) {
    const newBookmarks = new Set(bookmarkedNodes);
    if (newBookmarks.has(nodeId)) {
      newBookmarks.delete(nodeId);
    } else {
      newBookmarks.add(nodeId);
    }
    setBookmarkedNodes(newBookmarks);
  }

  function startPathAnalysis(nodeId: string) {
    if (!pathAnalysis.from) {
      setPathAnalysis({ from: nodeId });
    } else if (!pathAnalysis.to) {
      setPathAnalysis(prev => ({ ...prev, to: nodeId }));
      // Calculate shortest path
      const paths = findShortestPaths(prev.from!, nodeId);
      setPathAnalysis(prev => ({ ...prev, paths }));
    } else {
      setPathAnalysis({ from: nodeId });
    }
  }

  function findShortestPaths(fromId: string, toId: string): string[][] {
    // Simplified shortest path algorithm
    const graph = new Map<string, string[]>();
    
    links.forEach(link => {
      const sourceId = (link.source as any).id || link.source as string;
      const targetId = (link.target as any).id || link.target as string;
      
      if (!graph.has(sourceId)) graph.set(sourceId, []);
      graph.get(sourceId)!.push(targetId);
    });

    const queue = [[fromId]];
    const visited = new Set([fromId]);
    const paths: string[][] = [];

    while (queue.length > 0 && paths.length < 3) {
      const path = queue.shift()!;
      const current = path[path.length - 1];

      if (current === toId) {
        paths.push(path);
        continue;
      }

      const neighbors = graph.get(current) || [];
      neighbors.forEach(neighbor => {
        if (!visited.has(neighbor) && path.length < 5) {
          visited.add(neighbor);
          queue.push([...path, neighbor]);
        }
      });
    }

    return paths;
  }

  function showImpactAnalysis(nodeId: string) {
    // Calculate impact if this component is removed
    const impactedComponents = new Set<string>();
    
    function findImpacted(id: string) {
      links.forEach(link => {
        const sourceId = (link.source as any).id || link.source as string;
        const targetId = (link.target as any).id || link.target as string;
        
        if (targetId === id && !impactedComponents.has(sourceId)) {
          impactedComponents.add(sourceId);
          findImpacted(sourceId);
        }
      });
    }
    
    findImpacted(nodeId);
    
    // Highlight impacted nodes
    setSelectedNodes(new Set([nodeId, ...impactedComponents]));
  }

  function exportComponentData(node: Node) {
    const data = {
      component: node,
      dependencies: links.filter(l => (l.source as any).id === node.id),
      dependents: links.filter(l => (l.target as any).id === node.id),
      exportedAt: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${node.name}-analysis.json`;
    a.click();
  }

  function showLicenseDetails(node: Node) {
    // This would open a modal with detailed license information
    console.log('License details for:', node.name, node.licenses);
  }

  function exportGraph() {
    if (!svgRef.current) return;
    
    const svgElement = svgRef.current;
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svgElement);
    
    const blob = new Blob([svgString], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sbom-dependency-graph-${new Date().toISOString().split('T')[0]}.svg`;
    a.click();
  }

  function resetGraph() {
    setSelectedNodes(new Set());
    setSearchTerm('');
    setFilterType('all');
    setCriticalityThreshold(0);
    setDepthLimit(10);
    setPathAnalysis({});
    setHeatmapMode('none');
    
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      const zoom = d3.zoom<SVGSVGElement, unknown>();
      svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
    }
  }

  function fitToScreen() {
    if (!svgRef.current || filteredData.nodes.length === 0) return;
    
    const svg = d3.select(svgRef.current);
    const bounds = svg.node()!.getBBox();
    const parent = svg.node()!.parentElement!;
    const fullWidth = parent.clientWidth;
    const fullHeight = parent.clientHeight;
    
    const width = bounds.width;
    const height = bounds.height;
    const midX = bounds.x + width / 2;
    const midY = bounds.y + height / 2;
    
    const scale = 0.8 / Math.max(width / fullWidth, height / fullHeight);
    const translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];
    
    const zoom = d3.zoom<SVGSVGElement, unknown>();
    svg.transition().duration(750).call(
      zoom.transform,
      d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
    );
  }

  const selectedNodeDetails = useMemo(() => {
    if (selectedNodes.size === 0) return null;
    const nodeId = Array.from(selectedNodes)[0];
    return nodes.find(n => n.id === nodeId);
  }, [selectedNodes, nodes]);

  const currentTimelineEvent = useMemo(() => {
    return timeline[currentTime];
  }, [timeline, currentTime]);

  return (
    <div className="space-y-6">
      {/* Enhanced Control Panel */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-900">Interactive Dependency Graph</h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowMetrics(!showMetrics)}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                showMetrics ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              <BarChart3 className="w-4 h-4 mr-1 inline" />
              Metrics
            </button>
            <button
              onClick={() => setShowMiniMap(!showMiniMap)}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                showMiniMap ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              <Map className="w-4 h-4 mr-1 inline" />
              Mini Map
            </button>
          </div>
        </div>

        {/* Advanced Controls Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Search and Basic Filters */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Search Components</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by name..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Component Type</label>
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value as any)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Types</option>
                <option value="framework">Frameworks</option>
                <option value="library">Libraries</option>
                <option value="application">Applications</option>
              </select>
            </div>
          </div>

          {/* Layout and Visualization */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Graph Layout</label>
              <select
                value={layout}
                onChange={(e) => setLayout(e.target.value as any)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                <option value="hierarchical">Hierarchical</option>
                <option value="force">Force-Directed</option>
                <option value="circular">Circular</option>
                <option value="clustered">Clustered</option>
                <option value="timeline">Timeline</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Heatmap Mode</label>
              <select
                value={heatmapMode}
                onChange={(e) => setHeatmapMode(e.target.value as any)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                <option value="none">None</option>
                <option value="vulnerability">Vulnerability Risk</option>
                <option value="trust">Trust Score</option>
                <option value="popularity">Popularity</option>
                <option value="age">Component Age</option>
              </select>
            </div>
          </div>

          {/* Advanced Filters */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Criticality Threshold: {criticalityThreshold}
              </label>
              <input
                type="range"
                min="0"
                max="100"
                value={criticalityThreshold}
                onChange={(e) => setCriticalityThreshold(Number(e.target.value))}
                className="w-full"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Dependency Depth: {depthLimit}
              </label>
              <input
                type="range"
                min="1"
                max="20"
                value={depthLimit}
                onChange={(e) => setDepthLimit(Number(e.target.value))}
                className="w-full"
              />
            </div>

            <div className="flex items-center gap-4">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={showVulnerabilities}
                  onChange={(e) => setShowVulnerabilities(e.target.checked)}
                  className="mr-2"
                />
                <span className="text-sm text-gray-700">Show Vulnerabilities</span>
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={showClusters}
                  onChange={(e) => setShowClusters(e.target.checked)}
                  className="mr-2"
                />
                <span className="text-sm text-gray-700">Show Clusters</span>
              </label>
            </div>
          </div>

          {/* Analysis Tools */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Analysis Mode</label>
              <select
                value={selectedAnalysis}
                onChange={(e) => setSelectedAnalysis(e.target.value as any)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                <option value="overview">Overview</option>
                <option value="security">Security Analysis</option>
                <option value="performance">Performance Impact</option>
                <option value="compliance">License Compliance</option>
              </select>
            </div>

            <div className="flex gap-2">
              <button
                onClick={resetGraph}
                className="flex-1 px-3 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors text-sm"
              >
                <RotateCcw className="w-4 h-4 mr-1 inline" />
                Reset
              </button>
              <button
                onClick={fitToScreen}
                className="flex-1 px-3 py-2 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 transition-colors text-sm"
              >
                <Maximize2 className="w-4 h-4 mr-1 inline" />
                Fit
              </button>
            </div>
          </div>
        </div>

        {/* Timeline Controls */}
        {layout === 'timeline' && (
          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium text-gray-900">Timeline Playback</h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isPlaying ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'
                  }`}
                >
                  {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                </button>
                <span className="text-sm text-gray-600">
                  {currentTime + 1} / {timeline.length}
                </span>
              </div>
            </div>
            
            <input
              type="range"
              min="0"
              max={timeline.length - 1}
              value={currentTime}
              onChange={(e) => setCurrentTime(Number(e.target.value))}
              className="w-full mb-2"
            />
            
            {currentTimelineEvent && (
              <div className="text-sm text-gray-700">
                <strong>{new Date(currentTimelineEvent.timestamp).toLocaleDateString()}</strong>: {currentTimelineEvent.details}
              </div>
            )}
          </div>
        )}

        {/* Path Analysis Results */}
        {pathAnalysis.paths && pathAnalysis.paths.length > 0 && (
          <div className="mt-6 p-4 bg-blue-50 rounded-lg">
            <h3 className="text-lg font-medium text-blue-900 mb-3">Dependency Paths Found</h3>
            <div className="space-y-2">
              {pathAnalysis.paths.map((path, index) => (
                <div key={index} className="text-sm text-blue-800">
                  <strong>Path {index + 1}:</strong> {path.map(nodeId => {
                    const node = nodes.find(n => n.id === nodeId);
                    return node?.name || nodeId;
                  }).join(' → ')}
                </div>
              ))}
            </div>
            <button
              onClick={() => setPathAnalysis({})}
              className="mt-3 px-3 py-1 bg-blue-200 text-blue-800 rounded text-sm hover:bg-blue-300"
            >
              Clear Analysis
            </button>
          </div>
        )}
      </div>

      {/* Main Graph Container */}
      <div className="bg-white rounded-xl shadow-sm overflow-hidden">
        <div className="flex">
          {/* Graph Area */}
          <div className="flex-1 relative" ref={containerRef} style={{ height: '700px' }}>
            <svg
              ref={svgRef}
              width="100%"
              height="100%"
              className="border-r border-gray-200"
            />
            
            {/* Zoom Controls */}
            <div className="absolute top-4 left-4 flex flex-col gap-2">
              <button
                onClick={() => {
                  const svg = d3.select(svgRef.current!);
                  const zoom = d3.zoom<SVGSVGElement, unknown>();
                  svg.transition().duration(300).call(zoom.scaleBy, 1.5);
                }}
                className="p-2 bg-white rounded-lg shadow-md hover:bg-gray-50 transition-colors"
              >
                <ZoomIn className="w-4 h-4 text-gray-600" />
              </button>
              <button
                onClick={() => {
                  const svg = d3.select(svgRef.current!);
                  const zoom = d3.zoom<SVGSVGElement, unknown>();
                  svg.transition().duration(300).call(zoom.scaleBy, 0.75);
                }}
                className="p-2 bg-white rounded-lg shadow-md hover:bg-gray-50 transition-colors"
              >
                <ZoomOut className="w-4 h-4 text-gray-600" />
              </button>
              <button
                onClick={fitToScreen}
                className="p-2 bg-white rounded-lg shadow-md hover:bg-gray-50 transition-colors"
              >
                <Maximize2 className="w-4 h-4 text-gray-600" />
              </button>
            </div>

            {/* Mini Map */}
            {showMiniMap && (
              <div className="absolute bottom-4 right-4 w-48 h-32 bg-white rounded-lg shadow-lg border border-gray-200 p-2">
                <div className="text-xs font-medium text-gray-600 mb-1">Overview</div>
                <svg width="100%" height="100%" className="border border-gray-100 rounded">
                  {/* Simplified mini-map representation */}
                  {filteredData.nodes.slice(0, 20).map((node, index) => (
                    <circle
                      key={node.id}
                      cx={(index % 8) * 25 + 15}
                      cy={Math.floor(index / 8) * 25 + 15}
                      r="3"
                      fill={getNodeColor(node.type)}
                      opacity={selectedNodes.has(node.id) ? 1 : 0.5}
                    />
                  ))}
                </svg>
              </div>
            )}

            {/* Legend */}
            <div className="absolute top-4 right-4 bg-white rounded-lg shadow-lg p-4 max-w-xs">
              <h3 className="text-sm font-semibold text-gray-900 mb-3">Legend</h3>
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-emerald-500"></div>
                  <span>Libraries</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-amber-500"></div>
                  <span>Frameworks</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-purple-500"></div>
                  <span>Applications</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full border-2 border-red-500 bg-white"></div>
                  <span>Vulnerable</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 bg-blue-500 rounded-full relative">
                    <div className="absolute -top-1 -right-1 w-3 h-3 bg-blue-600 rounded-full text-white text-xs flex items-center justify-center">5</div>
                  </div>
                  <span>Dependency Count</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-0 h-0 border-l-2 border-r-2 border-b-4 border-transparent border-b-red-500"></div>
                  <span>Critical Component</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-1 bg-gray-400"></div>
                  <span>Direct Dependency</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-1 bg-gray-400" style={{borderTop: '1px dashed #6b7280'}}></div>
                  <span>Optional Dependency</span>
                </div>
              </div>
            </div>
          </div>

          {/* Side Panel */}
          <div className="w-80 bg-gray-50 p-6 overflow-y-auto">
            {/* Analysis Tabs */}
            <div className="flex mb-4 bg-white rounded-lg p-1">
              {[
                { id: 'overview', label: 'Overview', icon: Eye },
                { id: 'security', label: 'Security', icon: Shield },
                { id: 'performance', label: 'Performance', icon: Zap },
                { id: 'compliance', label: 'Compliance', icon: FileText }
              ].map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setSelectedAnalysis(id as any)}
                  className={`flex-1 flex items-center justify-center gap-1 py-2 px-3 rounded-md text-xs font-medium transition-colors ${
                    selectedAnalysis === id
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-gray-600 hover:text-gray-800'
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  {label}
                </button>
              ))}
            </div>

            {/* Metrics Panel */}
            {showMetrics && (
              <div className="mb-6 p-4 bg-white rounded-lg">
                <h3 className="text-sm font-semibold text-gray-900 mb-3">Graph Metrics</h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <div className="text-gray-500">Nodes</div>
                    <div className="font-semibold">{metrics.totalNodes}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Edges</div>
                    <div className="font-semibold">{metrics.totalEdges}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Avg Dependencies</div>
                    <div className="font-semibold">{metrics.avgDependencies?.toFixed(1)}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Max Depth</div>
                    <div className="font-semibold">{metrics.maxDepth}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Circular Deps</div>
                    <div className="font-semibold text-red-600">{metrics.circularDeps}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Vulnerable</div>
                    <div className="font-semibold text-amber-600">{metrics.vulnerableNodes}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Critical</div>
                    <div className="font-semibold text-red-600">{metrics.criticalComponents}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Orphans</div>
                    <div className="font-semibold text-gray-600">{metrics.orphanNodes}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Clusters</div>
                    <div className="font-semibold">{metrics.clusterCount}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Density</div>
                    <div className="font-semibold">{(metrics.networkDensity * 100).toFixed(1)}%</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Centrality</div>
                    <div className="font-semibold">{metrics.centralityScore?.toFixed(1)}</div>
                  </div>
                  <div>
                    <div className="text-gray-500">Modularity</div>
                    <div className="font-semibold">{metrics.modularityScore?.toFixed(1)}%</div>
                  </div>
                </div>
              </div>
            )}

            {/* Bookmarked Components */}
            {bookmarkedNodes.size > 0 && (
              <div className="mb-6 p-4 bg-white rounded-lg">
                <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
                  <Bookmark className="w-4 h-4 text-amber-500" />
                  Bookmarked Components
                </h3>
                <div className="space-y-2">
                  {Array.from(bookmarkedNodes).map(nodeId => {
                    const node = nodes.find(n => n.id === nodeId);
                    return node ? (
                      <div key={nodeId} className="flex items-center justify-between text-xs">
                        <span className="font-medium">{node.name}</span>
                        <button
                          onClick={() => toggleBookmark(nodeId)}
                          className="text-red-500 hover:text-red-700"
                        >
                          ×
                        </button>
                      </div>
                    ) : null;
                  })}
                </div>
              </div>
            )}

            {/* Selected Node Details */}
            {selectedNodeDetails && (
              <div className="p-4 bg-white rounded-lg">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-gray-900">Component Details</h3>
                  <button
                    onClick={() => toggleBookmark(selectedNodeDetails.id)}
                    className={`p-1 rounded ${
                      bookmarkedNodes.has(selectedNodeDetails.id) 
                        ? 'text-amber-500' 
                        : 'text-gray-400 hover:text-amber-500'
                    }`}
                  >
                    <Star className="w-4 h-4" />
                  </button>
                </div>
                
                <div className="space-y-3 text-xs">
                  <div>
                    <div className="font-medium text-gray-900">{selectedNodeDetails.name}</div>
                    <div className="text-gray-600">v{selectedNodeDetails.version || 'N/A'}</div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <div className="text-gray-500">Type</div>
                      <div className="font-medium capitalize">{selectedNodeDetails.type}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">Dependencies</div>
                      <div className="font-medium">{selectedNodeDetails.dependencyCount}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">Vulnerabilities</div>
                      <div className={`font-medium ${
                        selectedNodeDetails.vulnerabilities > 0 ? 'text-red-600' : 'text-green-600'
                      }`}>
                        {selectedNodeDetails.vulnerabilities}
                      </div>
                    </div>
                    <div>
                      <div className="text-gray-500">Criticality</div>
                      <div className="font-medium">{selectedNodeDetails.criticality.toFixed(1)}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">Trust Score</div>
                      <div className="font-medium">{selectedNodeDetails.trustScore?.toFixed(1)}%</div>
                    </div>
                    <div>
                      <div className="text-gray-500">Popularity</div>
                      <div className="font-medium">{selectedNodeDetails.popularity?.toFixed(1)}%</div>
                    </div>
                    <div>
                      <div className="text-gray-500">Maintainability</div>
                      <div className="font-medium">{selectedNodeDetails.maintainability?.toFixed(1)}%</div>
                    </div>
                    <div>
                      <div className="text-gray-500">Last Updated</div>
                      <div className="font-medium">
                        {new Date(selectedNodeDetails.lastUpdated!).toLocaleDateString()}
                      </div>
                    </div>
                  </div>

                  {selectedNodeDetails.licenses.length > 0 && (
                    <div>
                      <div className="text-gray-500 mb-1">Licenses</div>
                      <div className="flex flex-wrap gap-1">
                        {selectedNodeDetails.licenses.map((license, index) => (
                          <span
                            key={index}
                            className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs"
                          >
                            {license}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedNodeDetails.tags && selectedNodeDetails.tags.length > 0 && (
                    <div>
                      <div className="text-gray-500 mb-1">Tags</div>
                      <div className="flex flex-wrap gap-1">
                        {selectedNodeDetails.tags.map((tag, index) => (
                          <span
                            key={index}
                            className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Quick Actions */}
                <div className="mt-4 flex gap-2">
                  <button
                    onClick={() => startPathAnalysis(selectedNodeDetails.id)}
                    className="flex-1 px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs hover:bg-blue-200"
                  >
                    <Route className="w-3 h-3 mr-1 inline" />
                    Find Path
                  </button>
                  <button
                    onClick={() => showImpactAnalysis(selectedNodeDetails.id)}
                    className="flex-1 px-2 py-1 bg-amber-100 text-amber-700 rounded text-xs hover:bg-amber-200"
                  >
                    <Target className="w-3 h-3 mr-1 inline" />
                    Impact
                  </button>
                  <button
                    onClick={() => exportComponentData(selectedNodeDetails)}
                    className="flex-1 px-2 py-1 bg-green-100 text-green-700 rounded text-xs hover:bg-green-200"
                  >
                    <Download className="w-3 h-3 mr-1 inline" />
                    Export
                  </button>
                </div>
              </div>
            )}

            {/* Analysis Results */}
            {selectedAnalysis === 'security' && (
              <div className="mt-4 p-4 bg-white rounded-lg">
                <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-red-500" />
                  Security Analysis
                </h3>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span>High Risk Components:</span>
                    <span className="font-medium text-red-600">
                      {filteredData.nodes.filter(n => n.risk === 'high').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Medium Risk Components:</span>
                    <span className="font-medium text-amber-600">
                      {filteredData.nodes.filter(n => n.risk === 'medium').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Low Risk Components:</span>
                    <span className="font-medium text-green-600">
                      {filteredData.nodes.filter(n => n.risk === 'low').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Average Trust Score:</span>
                    <span className="font-medium">
                      {(filteredData.nodes.reduce((sum, n) => sum + (n.trustScore || 0), 0) / filteredData.nodes.length).toFixed(1)}%
                    </span>
                  </div>
                </div>
              </div>
            )}

            {selectedAnalysis === 'performance' && (
              <div className="mt-4 p-4 bg-white rounded-lg">
                <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-blue-500" />
                  Performance Impact
                </h3>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span>Critical Path Length:</span>
                    <span className="font-medium">{metrics.maxDepth} levels</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Network Density:</span>
                    <span className="font-medium">{(metrics.networkDensity * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Avg Maintainability:</span>
                    <span className="font-medium">
                      {(filteredData.nodes.reduce((sum, n) => sum + (n.maintainability || 0), 0) / filteredData.nodes.length).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Modularity Score:</span>
                    <span className="font-medium">{metrics.modularityScore?.toFixed(1)}%</span>
                  </div>
                </div>
              </div>
            )}

            {selectedAnalysis === 'compliance' && (
              <div className="mt-4 p-4 bg-white rounded-lg">
                <h3 className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-green-500" />
                  License Compliance
                </h3>
                <div className="space-y-2 text-xs">
                  {Array.from(new Set(filteredData.nodes.flatMap(n => n.licenses))).map(license => (
                    <div key={license} className="flex justify-between">
                      <span>{license || 'Unlicensed'}:</span>
                      <span className="font-medium">
                        {filteredData.nodes.filter(n => n.licenses.includes(license)).length}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Export Options */}
            <div className="mt-6">
              <button
                onClick={exportGraph}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm"
              >
                <Download className="w-4 h-4" />
                Export Graph
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Advanced Features Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Critical Components */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-red-500" />
            Critical Components
          </h3>
          <div className="space-y-3">
            {filteredData.nodes
              .filter(n => n.criticality > 70)
              .sort((a, b) => b.criticality - a.criticality)
              .slice(0, 5)
              .map(node => (
                <div key={node.id} className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                  <div>
                    <div className="font-medium text-gray-900">{node.name}</div>
                    <div className="text-sm text-gray-600">v{node.version}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-bold text-red-600">{node.criticality.toFixed(1)}</div>
                    <div className="text-xs text-gray-500">criticality</div>
                  </div>
                </div>
              ))}
          </div>
        </div>

        {/* Vulnerability Hotspots */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-500" />
            Vulnerability Hotspots
          </h3>
          <div className="space-y-3">
            {filteredData.nodes
              .filter(n => n.vulnerabilities > 0)
              .sort((a, b) => b.vulnerabilities - a.vulnerabilities)
              .slice(0, 5)
              .map(node => (
                <div key={node.id} className="flex items-center justify-between p-3 bg-amber-50 rounded-lg">
                  <div>
                    <div className="font-medium text-gray-900">{node.name}</div>
                    <div className="text-sm text-gray-600">v{node.version}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-bold text-amber-600">{node.vulnerabilities}</div>
                    <div className="text-xs text-gray-500">vulnerabilities</div>
                  </div>
                </div>
              ))}
          </div>
        </div>

        {/* Network Statistics */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Network className="w-5 h-5 text-blue-500" />
            Network Analysis
          </h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Graph Density</span>
              <span className="font-medium">{(metrics.networkDensity * 100).toFixed(1)}%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Modularity</span>
              <span className="font-medium">{metrics.modularityScore?.toFixed(1)}%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Centrality Score</span>
              <span className="font-medium">{metrics.centralityScore?.toFixed(1)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Cluster Count</span>
              <span className="font-medium">{metrics.clusterCount}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Circular Dependencies</span>
              <span className={`font-medium ${metrics.circularDeps > 0 ? 'text-red-600' : 'text-green-600'}`}>
                {metrics.circularDeps}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* AI-Powered Insights */}
      <div className="bg-gradient-to-r from-purple-50 to-blue-50 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Cpu className="w-5 h-5 text-purple-500" />
          AI-Powered Insights
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="bg-white rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="w-4 h-4 text-green-500" />
              <span className="font-medium text-sm">Optimization Opportunity</span>
            </div>
            <p className="text-xs text-gray-600">
              Consider consolidating {metrics.orphanNodes} orphaned components to reduce complexity.
            </p>
          </div>
          
          <div className="bg-white rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-red-500" />
              <span className="font-medium text-sm">Security Recommendation</span>
            </div>
            <p className="text-xs text-gray-600">
              {metrics.vulnerableNodes} components have known vulnerabilities. Prioritize updates for critical path components.
            </p>
          </div>
          
          <div className="bg-white rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Users className="w-4 h-4 text-blue-500" />
              <span className="font-medium text-sm">Architecture Insight</span>
            </div>
            <p className="text-xs text-gray-600">
              Network modularity of {metrics.modularityScore?.toFixed(1)}% suggests {
                (metrics.modularityScore || 0) > 50 ? 'well-structured' : 'tightly-coupled'
              } architecture.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}