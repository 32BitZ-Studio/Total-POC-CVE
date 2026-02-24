class CreateClients < ActiveRecord::Migration[7.0]
  def change
    create_table :clients do |t|
      t.string :first_name
      t.string :last_name
      t.string :cpf
      t.string :phone
      t.string :email

      t.timestamps
    end
  end
end
