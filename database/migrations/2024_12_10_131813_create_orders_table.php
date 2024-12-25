<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('orders', function (Blueprint $table) {
            $table->id(); // Primary key
            $table->string('order_number')->unique(); // Unique order number
            $table->foreignId('customer_id')->constrained()->onDelete('cascade'); // Foreign key to customers
            $table->foreignId('service_id')->constrained()->onDelete('cascade'); // Foreign key to services
            $table->decimal('weight', 8, 2); // Weight with 2 decimal places
            $table->decimal('total_price', 10, 2); // Total price with 2 decimal places
            $table->enum('status', ['pending', 'process', 'completed', 'cancelled'])->default('pending'); // Order status
            $table->date('pickup_date')->nullable(); // Nullable pickup date
            $table->text('notes')->nullable(); // Optional notes
            $table->timestamps(); // Created and updated timestamps
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('orders');
    }
};
