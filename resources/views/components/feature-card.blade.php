@props(['icon', 'title', 'description'])

<div class="bg-white p-6 rounded-xl shadow-sm">
    <div class="w-12 h-12 bg-[#00B4D8]/10 rounded-lg flex items-center justify-center mb-4">
        <svg class="w-6 h-6 text-[#00B4D8]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="{{ $icon }}" />
        </svg>
    </div>
    <h3 class="text-lg font-semibold text-gray-900 mb-2">{{ $title }}</h3>
    <p class="text-gray-600">{{ $description }}</p>
</div> 