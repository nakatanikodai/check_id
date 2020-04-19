class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :authentication_keys => [:user_id]

  validates_uniqueness_of :user_id
  validates_presence_of :user_id

  
  def self.find_first_by_auth_conditions(warden_conditions)
    conditions = warden_conditions.dup
    if login = conditions.delete(:login)
      
      where(conditions).where(["user_id = :value", {:value => user_id}]).first
    else
      where(conditions).first
    end 
  end 

  def email_required?
    false
  end

  def email_changed?
    false
  end
end
