-- Add foreign key constraint for subscription_id in payments table
ALTER TABLE payments 
ADD CONSTRAINT fk_payments_subscription_id 
FOREIGN KEY (subscription_id) REFERENCES subscriptions(id);
