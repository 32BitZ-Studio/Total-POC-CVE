FactoryBot.define do
    factory :client do
      first_name { Faker::Name.first_name }
      last_name { Faker::Name.last_name }
      cpf { Faker::IDNumber.brazilian_citizen_number }
      phone { Faker::PhoneNumber.phone_number }
      email { Faker::Internet.email }
    end
  end