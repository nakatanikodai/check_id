class AddUserIdIndexToUsers < ActiveRecord::Migration[5.2]
  def change
    add_index :users, :user_id, unique: true
  end
end
