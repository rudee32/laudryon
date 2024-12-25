@props(['active'])

@php
$classes = ($active ?? false)
    ? 'flex items-center px-4 py-2 text-[#00B4D8] bg-[#00B4D8]/10 rounded-lg'
    : 'flex items-center px-4 py-2 text-gray-500 hover:text-[#00B4D8] hover:bg-[#00B4D8]/10 rounded-lg transition-colors duration-200';
@endphp

<a {{ $attributes->merge(['class' => $classes]) }}>
    {{ $slot }}
</a>
