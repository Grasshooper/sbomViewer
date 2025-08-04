import React, { useState, useMemo } from 'react';
import { Upload, Search, Filter, FileText, Shield, Users, Download, Eye, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { SBOMData, Component } from './types/sbom';
import { ComponentTree } from './components/ComponentTree';
import { ComponentDetails } from './components/ComponentDetails';
import { SecurityOverview } from './components/SecurityOverview';
import { LicenseOverview } from './components/LicenseOverview';
import { DependencyGraph } from './components/DependencyGraph';
import { InteractiveDependencyGraph } from './components/InteractiveDependencyGraph';
import { SearchAndFilter } from './components/SearchAndFilter';
import { StatCard } from './components/StatCard';

function App() {
  const [sbomData, setSbomData] = useState<SBOMData | null>(null);
  const [selectedComponent, setSelectedComponent] = useState<Component | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'components' | 'dependencies' | 'security' | 'licenses'>('overview');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'framework' | 'library' | 'application'>('all');

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const json = JSON.parse(e.target?.result as string);
          setSbomData(json);
          setActiveTab('overview');
        } catch (error) {
          console.error('Error parsing SBOM file:', error);
          alert('Error parsing SBOM file. Please check the file format.');
        }
      };
      reader.readAsText(file);
    }
  };

  const filteredComponents = useMemo(() => {
    if (!sbomData?.components) return [];
    
    return sbomData.components.filter(component => {
      const matchesSearch = component.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           component.version?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           component.description?.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesFilter = filterType === 'all' || component.type === filterType;
      
      return matchesSearch && matchesFilter;
    });
  }, [sbomData?.components, searchTerm, filterType]);

  const stats = useMemo(() => {
    if (!sbomData?.components) return { total: 0, libraries: 0, frameworks: 0, applications: 0 };
    
    const components = sbomData.components;
    return {
      total: components.length,
      libraries: components.filter(c => c.type === 'library').length,
      frameworks: components.filter(c => c.type === 'framework').length,
      applications: components.filter(c => c.type === 'application').length,
    };
  }, [sbomData?.components]);

  if (!sbomData) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-4">
        <div className="bg-white rounded-xl shadow-lg p-8 max-w-md w-full">
          <div className="text-center">
            <FileText className="w-16 h-16 text-blue-600 mx-auto mb-4" />
            <h1 className="text-2xl font-bold text-gray-900 mb-2">SBOM Viewer</h1>
            <p className="text-gray-600 mb-6">Upload your Software Bill of Materials to get started</p>
            
            <label className="block">
              <input
                type="file"
                accept=".json"
                onChange={handleFileUpload}
                className="hidden"
              />
              <div className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg cursor-pointer transition-colors duration-200 inline-flex items-center gap-2">
                <Upload className="w-5 h-5" />
                Upload SBOM File
              </div>
            </label>
            
            <p className="text-sm text-gray-500 mt-4">
              Supports CycloneDX JSON format
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">SBOM Viewer</h1>
                <p className="text-sm text-gray-600">{sbomData.metadata?.component?.name || 'Unnamed Project'}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <button
                onClick={() => {
                  const dataStr = JSON.stringify(sbomData, null, 2);
                  const dataBlob = new Blob([dataStr], { type: 'application/json' });
                  const url = URL.createObjectURL(dataBlob);
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = 'sbom-export.json';
                  link.click();
                }}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                <Download className="w-4 h-4" />
                Export
              </button>
              
              <label className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-lg hover:bg-blue-700 transition-colors cursor-pointer">
                <Upload className="w-4 h-4" />
                New SBOM
                <input
                  type="file"
                  accept=".json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {[
              { id: 'overview', label: 'Overview', icon: Eye },
              { id: 'components', label: 'Components', icon: FileText },
              { id: 'dependencies', label: 'Dependencies', icon: Users },
              { id: 'security', label: 'Security', icon: Shield },
              { id: 'licenses', label: 'Licenses', icon: FileText },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id as any)}
                className={`flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* Project Info */}
            <div className="bg-white rounded-xl shadow-sm p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Project Information</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm font-medium text-gray-500">Project Name</p>
                  <p className="text-lg font-semibold text-gray-900">{sbomData.metadata?.component?.name || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Version</p>
                  <p className="text-lg font-semibold text-gray-900">{sbomData.metadata?.component?.version || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Format</p>
                  <p className="text-lg font-semibold text-gray-900">{sbomData.bomFormat} {sbomData.specVersion}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Generated</p>
                  <p className="text-lg font-semibold text-gray-900">
                    {sbomData.metadata?.timestamp ? new Date(sbomData.metadata.timestamp).toLocaleDateString() : 'N/A'}
                  </p>
                </div>
              </div>
            </div>

            {/* Statistics */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              <StatCard
                title="Total Components"
                value={stats.total}
                icon={FileText}
                color="blue"
              />
              <StatCard
                title="Libraries"
                value={stats.libraries}
                icon={FileText}
                color="emerald"
              />
              <StatCard
                title="Frameworks"
                value={stats.frameworks}
                icon={Shield}
                color="amber"
              />
              <StatCard
                title="Applications"
                value={stats.applications}
                icon={Users}
                color="purple"
              />
            </div>

            {/* Quick Actions */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <button
                onClick={() => setActiveTab('components')}
                className="bg-white rounded-xl shadow-sm p-6 text-left hover:shadow-md transition-shadow group"
              >
                <FileText className="w-8 h-8 text-blue-600 mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Explore Components</h3>
                <p className="text-gray-600">Browse through all software components with detailed information</p>
              </button>
              
              <button
                onClick={() => setActiveTab('security')}
                className="bg-white rounded-xl shadow-sm p-6 text-left hover:shadow-md transition-shadow group"
              >
                <Shield className="w-8 h-8 text-emerald-600 mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Security Analysis</h3>
                <p className="text-gray-600">Review security vulnerabilities and risk assessments</p>
              </button>
              
              <button
                onClick={() => setActiveTab('licenses')}
                className="bg-white rounded-xl shadow-sm p-6 text-left hover:shadow-md transition-shadow group"
              >
                <FileText className="w-8 h-8 text-amber-600 mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">License Overview</h3>
                <p className="text-gray-600">Manage license compliance and obligations</p>
              </button>
            </div>
          </div>
        )}

        {activeTab === 'components' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-1">
              <div className="bg-white rounded-xl shadow-sm">
                <div className="p-6 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900 mb-4">Components</h2>
                  <SearchAndFilter
                    searchTerm={searchTerm}
                    onSearchChange={setSearchTerm}
                    filterType={filterType}
                    onFilterChange={setFilterType}
                  />
                </div>
                <div className="max-h-96 overflow-y-auto">
                  <ComponentTree
                    components={filteredComponents}
                    selectedComponent={selectedComponent}
                    onSelectComponent={setSelectedComponent}
                  />
                </div>
              </div>
            </div>
            
            <div className="lg:col-span-2">
              {selectedComponent ? (
                <ComponentDetails component={selectedComponent} />
              ) : (
                <div className="bg-white rounded-xl shadow-sm p-8 text-center">
                  <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Component</h3>
                  <p className="text-gray-600">Choose a component from the list to view detailed information</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'dependencies' && (
          <InteractiveDependencyGraph sbomData={sbomData} />
        )}

        {activeTab === 'security' && (
          <SecurityOverview components={sbomData.components || []} />
        )}

        {activeTab === 'licenses' && (
          <LicenseOverview components={sbomData.components || []} />
        )}
      </main>
    </div>
  );
}

export default App;