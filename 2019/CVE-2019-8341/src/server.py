from flask import Flask, request, render_template_string, send_from_directory


app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string(open("/app/src/content/home.html").read())



search_results = """
    {%for i in range(0, len)%}
    
        <li>{{data[i]}}</li>
    {%endfor%}
"""

@app.route('/search', methods=['POST'])
def search():
    if request.method == "POST":
        query = request.form['a']
        found_facts = llama_facts(query)

        response = "Your query: " + query + "\n\n" + search_results
        return render_template_string(
            response, len = len(found_facts), data=found_facts
        )
    # return f"you searched {query}"

@app.route("/css/css.css")
def css():
    return send_from_directory("/app/src/css", "css.css")

@app.route("/css/bootstrap.min/css")
def css1():
    return send_from_directory("/app/src/css", "bootstrap.min.css")

def llama_facts(q):
    """return query and first fact to match query"""
    return [x for x in facts if q in x]

facts = ["Llamas are members of the camelid family meaning they're pretty closely related to vicuñas and camels.",
 "Camelids first appeared on the Central Plains of North America about 40 million years ago. About 3 million years ago, llamas' ancestors migrated to South America.",
 'During the last ice age (10,000-12,000 years ago) camelids went extinct in North America. Now there are around 160,000 llamas and 100,000 alpacas in the United States and Canada.',
 'Llamas were first domesticated and used as pack animals 4,000 to 5,000 years ago in the Peruvian highlands.',
 'Llamas can grow as much as 6 feet tall though the average llama between 5 feet 6 inches and 5 feet 9 inches tall.',
 'Llamas weigh between 280 and 450 pounds and can carry 25 to 30 percent of their body weight, so a 400-pound male llama can carry about 100 to 120 pounds on a trek of 10 to 12 miles with no problem.',
 'Llamas know their own limits. If you try to overload a llama with too much weight, the llama is likely to lie down or simply refuse to move.',
 'In the Andes Mountains of Peru, llama fleece has been shorn and used in textiles for about 6,000 years. Llama wool is light, warm, water-repellent, and free of lanolin.',
 'Llamas are hardy and well suited to harsh environments. They are quite sure-footed, easily navigating rocky terrain at high altitudes.',
 'Llamas are smart and easy to train.',
 "Llamas have been used as guard animals for livestock like sheep or even alpacas in North America since the '80s. They require almost no training to be an effective guard.",
 "Llamas don't bite. They spit when they're agitated, but that's mostly at each other. Llamas also kick and neck wrestle each other when agitated.",
 'Llamas are vegetarians and have very efficient digestive systems.',
 "A llama's stomach has three compartments. They are called the rumen, omasum, and abomasum. A cow's stomach has four compartments. Like cows, llamas must regurgitate and re-chew their food to digest it completely.",
 'Llama poop has almost no odor. Llama farmers refer to llama manure as "llama beans." It makes for a great, eco-friendly fertilizer. Historically, the Incas in Peru burned dried llama poop for fuel.',
 'Llamas live to be about 20 years old. Though some only live for 15 years and others live to be 30 years old.',
 'A baby llama is called a "cria" which is Spanish for baby. It\'s pronounced KREE-uh. Baby alpacas, vicuñas, and guanacos are also called crias. Mama llamas usually only have one baby at a time and llama twins are incredibly rare. Pregnancy lasts for about 350 days, nearly a full year. Crias weigh 20 to 35 pounds at birth.',
 'Llamas come in a range of solid and spotted colors including black, gray, beige, brown, red, and white.',
 'Llamas are social animals and prefer to live with other llamas or herd animals. The social structure of llamas changes frequently and a male llama can move up the social ladder by picking, and winning, small fights with the leader of the group.',
 'A group of llamas is called a herd.',
 'Llamas have two wild "cousins" that have never been domesticated: the vicuña and the guanaco. The Guanaco is closely related to the llama. Vicuñas are thought to be the ancestors of alpacas.',
 'The current population of llamas and alpacas in South America is estimated to be more than 7 million.',
 'Yarn made from llama fiber is soft and lightweight, yet remarkably warm. The soft, undercoat is used for garments and handicrafts while the coarse, outer coat is frequently used for rugs and ropes.',
 'Trying to tell the difference between a llama and an alpaca? Two obvious things to look for: Llamas are generally about twice the size of alpacas, and alpacas have short, pointy ears, whereas llamas have much longer ears that stand straight up and give them an alert look.']



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5656, debug=False)