<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class Order extends Model
{
    use HasFactory;

    protected static function boot()
    {
        parent::boot();
        
        static::creating(function ($order) {
            // Generate order number format: LDY-YYYYMMDD-XXXX
            $order->order_number = 'LDY-' . date('Ymd') . '-' . strtoupper(Str::random(4));
        });
    }

    protected $fillable = [
        'customer_id',
        'service_id',
        'total_price',
        'weight',
        'status',
        'pickup_date',
        'delivery_date',
        'order_number'
    ];

    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }

    public function service()
    {
        return $this->belongsTo(Service::class);
    }
} 