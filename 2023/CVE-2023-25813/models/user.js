module.exports = (sequelize,DataTypes)=>{
    return sequelize.define('user',{
        firstname:{
            type:DataTypes.STRING(40),
            allowNull:false,
            unique:false,
        },
        lastname: {
            type:DataTypes.STRING(40),
            allowNull:false,
            unique:false,
        },
        username:{
            type:DataTypes.STRING(40),
            allowNull:false,
            unique:false,
        },
        password:{
            type:DataTypes.STRING(100),
            allowNull:false,
        },
        email:{
            type:DataTypes.STRING(100),
            allowNull:true,
        }
    })
};