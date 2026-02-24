class Client < ApplicationRecord
    validates :first_name, presence: true
    validates :last_name, presence: true
    validates :cpf, presence: true
    validates :phone, presence: true
    validates :email, presence: true
end