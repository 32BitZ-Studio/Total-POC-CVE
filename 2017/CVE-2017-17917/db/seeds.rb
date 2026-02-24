15.times do |_s|
  Client.create(first_name: Faker::Name.first_name, last_name: Faker::Name.last_name, cpf: Faker::Number.binary(digits: 8), phone: Faker::PhoneNumber.cell_phone, email: Faker::Internet.email)
end

puts "================================="
puts <<-'COW'
   .--.
  |o_o |
  |:_/ |
 //   \ \
(|     | )
/'\_   _/`\
\___)=(___/
COW
puts "Happy code"
puts "================================="
