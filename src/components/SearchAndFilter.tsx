import React from 'react';
import { Search, Filter } from 'lucide-react';

interface SearchAndFilterProps {
  searchTerm: string;
  onSearchChange: (term: string) => void;
  filterType: 'all' | 'framework' | 'library' | 'application';
  onFilterChange: (type: 'all' | 'framework' | 'library' | 'application') => void;
}

export function SearchAndFilter({ searchTerm, onSearchChange, filterType, onFilterChange }: SearchAndFilterProps) {
  return (
    <div className="space-y-3">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
        <input
          type="text"
          placeholder="Search components..."
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
      </div>
      
      <div className="relative">
        <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
        <select
          value={filterType}
          onChange={(e) => onFilterChange(e.target.value as any)}
          className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent appearance-none bg-white"
        >
          <option value="all">All Types</option>
          <option value="framework">Frameworks</option>
          <option value="library">Libraries</option>
          <option value="application">Applications</option>
        </select>
      </div>
    </div>
  );
}